// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "port_out.h"
#include "../utils/format.h"
#include "../utils/hashing.h"

using bess::utils::hash_range;

CommandResponse PortOut::Init(const bess::pb::PortOutArg &arg) {
  const char *port_name;
  int ret;

  if (!arg.port().length()) {
    return CommandFailure(EINVAL, "'port' must be given as a string");
  }

  port_name = arg.port().c_str();

  const auto &it = PortBuilder::all_ports().find(port_name);
  if (it == PortBuilder::all_ports().end()) {
    return CommandFailure(ENODEV, "Port %s not found", port_name);
  }
  port_ = it->second;

  if (port_->num_queues[PACKET_DIR_OUT] == 0) {
    return CommandFailure(ENODEV, "Port %s has no outgoing queue", port_name);
  }

  if (arg.tx_lb_mode() == "l2") {
    tx_lb_mode_ = TxLbMode::kL2;
  } else if (arg.tx_lb_mode() == "l3") {
    tx_lb_mode_ = TxLbMode::kL3;
  } else if (arg.tx_lb_mode() == "l4") {
    tx_lb_mode_ = TxLbMode::kL4;
  } else if (!arg.tx_lb_mode().empty()) {
    return CommandFailure(EINVAL,
                          "available TX LB modes: 'l2', 'l3', 'l4', and ''");
  }

  ret = port_->AcquireQueues(reinterpret_cast<const module *>(this),
                             PACKET_DIR_OUT, nullptr, 0);

  node_constraints_ = port_->GetNodePlacementConstraint();

  for (size_t i = 0; i < MAX_QUEUES_PER_DIR; i++) {
    mcs_lock_init(&queue_locks_[i]);
  }

  if (ret < 0) {
    return CommandFailure(-ret);
  }

  return CommandSuccess();
}

void PortOut::DeInit() {
  if (port_) {
    port_->ReleaseQueues(reinterpret_cast<const module *>(this), PACKET_DIR_OUT,
                         nullptr, 0);
  }
}

std::string PortOut::GetDesc() const {
  return bess::utils::Format("%s/%s", port_->name().c_str(),
                             port_->port_builder()->class_name().c_str());
}

void PortOut::SendBatch(bess::PacketBatch *batch, queue_t qid) {
  Port *p = port_;

  mcslock_node_t me;
  uint64_t sent_bytes = 0;
  int sent_pkts = 0;

  mcs_lock(&queue_locks_[qid], &me);
  if (p->conf().admin_up) {
    sent_pkts = p->SendPackets(qid, batch->pkts(), batch->cnt());
  }

  if (!(p->GetFlags() & DRIVER_FLAG_SELF_OUT_STATS)) {
    const packet_dir_t dir = PACKET_DIR_OUT;

    for (int j = 0; j < sent_pkts; j++) {
      sent_bytes += batch->pkts()[j]->total_len();
    }

    p->queue_stats[dir][qid].packets += sent_pkts;
    p->queue_stats[dir][qid].dropped += (batch->cnt() - sent_pkts);
    p->queue_stats[dir][qid].bytes += sent_bytes;
  }
  mcs_unlock(&queue_locks_[qid], &me);

  if (sent_pkts < batch->cnt()) {
    bess::Packet::Free(batch->pkts() + sent_pkts, batch->cnt() - sent_pkts);
  }
}

void SplitBatchL2(bess::PacketBatch *orig, bess::PacketBatch *batches,
                  queue_t num_queues) {
  size_t cnt = orig->cnt();
  for (size_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = orig->pkts()[i];
    queue_t qid = hash_range(bess::utils::HashPktL2(pkt), num_queues);
    batches[qid].add(pkt);
  }
}

void SplitBatchL3(bess::PacketBatch *orig, bess::PacketBatch *batches,
                  queue_t num_queues) {
  size_t cnt = orig->cnt();
  for (size_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = orig->pkts()[i];
    queue_t qid = hash_range(bess::utils::HashPktL3(pkt), num_queues);
    batches[qid].add(pkt);
  }
}

void SplitBatchL4(bess::PacketBatch *orig, bess::PacketBatch *batches,
                  queue_t num_queues) {
  size_t cnt = orig->cnt();
  for (size_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = orig->pkts()[i];
    queue_t qid = hash_range(bess::utils::HashPktL4(pkt), num_queues);
    batches[qid].add(pkt);
  }
}

void PortOut::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const queue_t num_queues = port_->num_queues[PACKET_DIR_OUT];

  if (tx_lb_mode_ == TxLbMode::kNone) {
    const queue_t qid = hash_range(ctx->current_igate, num_queues);
    SendBatch(batch, qid);
    return;
  }

  bess::PacketBatch batches[num_queues];
  for (int i = 0; i < num_queues; i++) {
    batches[i].clear();
  }

  switch (tx_lb_mode_) {
    case TxLbMode::kL2:
      SplitBatchL2(batch, batches, num_queues);
      break;
    case TxLbMode::kL3:
      SplitBatchL3(batch, batches, num_queues);
      break;
    case TxLbMode::kL4:
      SplitBatchL4(batch, batches, num_queues);
      break;
    default:
      DCHECK(0);
  }
  batch->clear();

  for (size_t i = 0; i < num_queues; i++) {
    if (batches[i].empty()) {
      continue;
    }
    SendBatch(&batches[i], i);
  }
}

ADD_MODULE(PortOut, "port_out", "sends pakets to a port")

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

#include "metadata.h"

#include <glog/logging.h>

#include <algorithm>
#include <functional>
#include <queue>

#include "mem_alloc.h"
#include "module.h"

namespace bess {
namespace metadata {

// TODO: Once the rest of the code supports multiple pipelines, this ought to be
// a collection of pipelines in bess::metadata a la Ports/Modules.
Pipeline default_pipeline;

// Helpers -----------------------------------------------------------------

static mt_offset_t ComputeNextOffset(mt_offset_t curr_offset, int8_t size) {
  uint32_t overflow;
  int8_t rounded_size;

  rounded_size = align_ceil_pow2(size);

  if (curr_offset % rounded_size) {
    curr_offset = align_ceil(curr_offset, rounded_size);
  }

  overflow = (uint32_t)curr_offset + (uint32_t)size;

  return overflow > kMetadataTotalSize ? kMetadataOffsetNoSpace : curr_offset;
}

// Generate warnings for modules that read metadata that never gets set.
static void CheckOrphanReaders() {
  for (const auto &it : ModuleBuilder::all_modules()) {
    const Module *m = it.second;
    if (!m) {
      break;
    }

    size_t i = 0;
    for (const auto &attr : m->all_attrs()) {
      if (m->attr_offset(i) == kMetadataOffsetNoRead) {
        LOG(WARNING) << "Metadata attr " << attr.name << "/" << attr.size
                     << " of module " << m->name() << " has "
                     << "no upstream module that sets the value!";
      }
      i++;
    }
  }
}

static const Attribute *FindAttr(Module *m, const Attribute &attr) {
  for (const auto &it : m->all_attrs()) {
    if (it.name == attr.name) {
      return &it;
    }
  }

  return nullptr;
}

// ScopeComponent ----------------------------------------------------------

class ScopeComponentComp {
 public:
  explicit ScopeComponentComp(const bool &revparam = false)
      : reverse_(revparam) {}

  bool operator()(const ScopeComponent *lhs, const ScopeComponent *rhs) const {
    if (reverse_) {
      return (lhs->offset() < rhs->offset());
    }
    return (lhs->offset() > rhs->offset());
  }

 private:
  bool reverse_;
};

static bool DegreeComp(const ScopeComponent &a, const ScopeComponent &b) {
  return a.degree() > b.degree();
}

bool ScopeComponent::DisjointFrom(const ScopeComponent &rhs) const {
  for (const Module *i : modules_) {
    for (const Module *j : rhs.modules_) {
      if (i == j) {
        return false;
      }
    }
  }
  return true;
}

// Pipeline ----------------------------------------------------------------

void Pipeline::CleanupMetadataComputation() {
  scopes_.clear();
}

static void GatherReaders(Module *u, ScopeComponent *scope,
                          std::vector<Module *> *modules,
                          std::set<Module *> *visited) {
  if (u == nullptr || visited->count(u)) {
    return;
  }
  visited->insert(u);
  modules->push_back(u);

  for (const auto &ogate : u->ogates()) {
    if (!ogate || !ogate->igate()) {
      continue;
    }
    Module *v = ogate->igate()->module();
    GatherReaders(v, scope, modules, visited);
  }

  const Attribute *attr = FindAttr(u, scope->attr());
  if (attr && attr->mode != Attribute::AccessMode::kWrite) {
    for (Module *v : *modules) {
      scope->add_module(v);
    }
  }
  modules->pop_back();
}

void Pipeline::FillOffsetArrays() {
  for (const ScopeComponent &scope : scopes_) {
    for (Module *m : scope.modules()) {
      size_t k = 0;
      for (const auto &attr : m->all_attrs()) {
        if (attr.name == scope.attr().name) {
          m->set_attr_offset(k, scope.offset());
          break;
        }
        k++;
      }
    }
  }
}

void Pipeline::AssignOffsets() {
  mt_offset_t offset = 0;
  ScopeComponent *comp1;
  const ScopeComponent *comp2;

  for (ScopeComponent &a : scopes_) {
    std::priority_queue<const ScopeComponent *,
                        std::vector<const ScopeComponent *>, ScopeComponentComp>
        h;
    comp1 = &a;

    if (comp1->assigned() || comp1->modules().size() == 1) {
      continue;
    }

    offset = 0;

    for (ScopeComponent &b : scopes_) {
      if (a.attr().name == b.attr().name) {
        continue;
      }

      if (!a.DisjointFrom(b) && b.assigned()) {
        h.push(&b);
      }
    }

    while (!h.empty()) {
      comp2 = h.top();
      h.pop();

      if (comp2->offset() == kMetadataOffsetNoRead ||
          comp2->offset() == kMetadataOffsetNoWrite ||
          comp2->offset() == kMetadataOffsetNoSpace) {
        continue;
      }

      if (offset + static_cast<mt_offset_t>(comp1->attr().size) >
          comp2->offset()) {
        offset = ComputeNextOffset(comp2->offset() + comp2->attr().size,
                                   comp1->attr().size);
      } else {
        break;
      }
    }

    comp1->set_offset(offset);
    comp1->set_assigned(true);
  }

  FillOffsetArrays();
}

void Pipeline::LogAllScopes() const {
  for (const auto &scope : scopes_) {
    VLOG(1) << "scope component for " << scope.attr().size << "-byte attr "
            << scope.attr().name << " at offset "
            << static_cast<int>(scope.offset()) << ": {";

    for (const auto &it_m : scope.modules()) {
      VLOG(1) << it_m->name();
    }

    VLOG(1) << "}";
  }
}

void Pipeline::ComputeScopeDegrees() {
  for (size_t i = 0; i < scopes_.size(); i++) {
    for (size_t j = i + 1; j < scopes_.size(); j++) {
      if (!scopes_[i].DisjointFrom(scopes_[j])) {
        scopes_[i].incr_degree();
        scopes_[j].incr_degree();
      }
    }
  }
}

// Main entry point for calculating metadata offsets.
int Pipeline::ComputeMetadataOffsets() {
  std::map<std::string, ScopeComponent *> scope_map;

  for (const auto &it : ModuleBuilder::all_modules()) {
    Module *m = it.second;
    if (!m) {
      continue;
    }

    size_t i = 0;
    for (const Attribute &attr : m->all_attrs()) {
      if (attr.mode == Attribute::AccessMode::kRead ||
          attr.mode == Attribute::AccessMode::kUpdate) {
        m->set_attr_offset(i, kMetadataOffsetNoRead);
      } else if (attr.mode == Attribute::AccessMode::kWrite) {
        m->set_attr_offset(i, kMetadataOffsetNoWrite);
        ScopeComponent *scope = scope_map[attr.name];
        if (scope == nullptr) {
          scopes_.emplace_back(attr);
          scope_map[attr.name] = scope = &scopes_.back();
        }
        std::vector<Module *> modules;
        std::set<Module *> visited;
        GatherReaders(m, scope, &modules, &visited);
      }
      i++;
    }
  }

  ComputeScopeDegrees();
  std::sort(scopes_.begin(), scopes_.end(), DegreeComp);
  AssignOffsets();

  if (VLOG_IS_ON(1)) {
    LogAllScopes();
  }

  CheckOrphanReaders();

  CleanupMetadataComputation();

  return 0;
}

int Pipeline::RegisterAttribute(const std::string &attr_name, size_t size) {
  const auto &it = registered_attrs_.find(attr_name);
  if (it == registered_attrs_.end()) {
    registered_attrs_.emplace(attr_name, std::make_tuple(size, 1));
    return 0;
  }

  size_t registered_size = std::get<0>(it->second);
  int &count = std::get<1>(it->second);

  if (registered_size == size) {
    count++;
    return 0;
  } else {
    LOG(ERROR) << "Attribute '" << attr_name
               << "' has size mismatch: registered(" << registered_size
               << ") vs new(" << size << ")";
    return -EINVAL;
  }
}

void Pipeline::DeregisterAttribute(const std::string &attr_name) {
  const auto &it = registered_attrs_.find(attr_name);
  if (it == registered_attrs_.end()) {
    LOG(ERROR) << "ReregisteredAttribute() called, but '" << attr_name
               << "' was not registered";
    return;
  }

  int &count = std::get<1>(it->second);

  count--;
  DCHECK_GE(count, 0);

  if (count == 0) {
    // No more modules are using the attribute. Remove it from the map.
    registered_attrs_.erase(it);
  }
}

}  // namespace metadata
}  // namespace bess

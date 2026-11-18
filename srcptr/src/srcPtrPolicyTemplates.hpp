/**
 * @file srcPtrPolicyTemplates.hpp
 *
 * @copyright Copyright (C) 2015-2016 srcML, LLC. (www.srcML.org)
 *
 * This file is part of srcPtr.
 *
 * srcPtr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * srcPtr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srcPtr.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INCLUDED_SRC_PTR_POLICY_TEMPLATES_HPP
#define INCLUDED_SRC_PTR_POLICY_TEMPLATES_HPP


#include <DisjointSet.hpp>
#include <srcPtrUtilities.hpp>

#include <set>
#include <iostream>
#include <map>
#include <string>
#include <vector>

class srcPtrEmptyAlgorithm {
public:
   ~srcPtrEmptyAlgorithm() { }; 

   void AddPointsToRelationship(Variable lhs, Variable rhs) { }

   void AddAssignmentRelationship(Variable lhs, Variable rhs) { }

   void AddLoadRelationship(Variable lhs, Variable ptr) { }

   void AddStoreRelationship(Variable ptr, Variable rhs) { }

   void Print() { }

   void PrintTSV() { }

   void PrintGraphViz() { }

   std::vector<Variable> GetPointsTo(Variable ptr) { return std::vector<Variable>(); }

   std::vector<Variable> GetPointers() { return std::vector<Variable>(); }

   srcPtrEmptyAlgorithm *Clone() const { return (new srcPtrEmptyAlgorithm(*this)); }
};

class srcPtrAndersen {
public:
   // Inclusion-based (Andersen) points-to analysis. Four kinds of constraint:
   //   p = &x, p = malloc(..)   pts(p) contains x / the allocation site
   //   q = p                     pts(q) includes pts(p)
   //   q = *p, q = p->f          pts(q) includes pts(o) for every o in pts(p)
   //   *p = q, p->f = q          pts(o) includes pts(q) for every o in pts(p)
   // solved to a fixed point. (The original queue-based version recursed to a fixed depth and cleared its queue, so
   // its result depended on the order of the statements, and it had no loads or stores.)
   ~srcPtrAndersen() { };

   void AddPointsToRelationship(Variable lhs, Variable rhs) { base[lhs].insert(rhs); nodes.insert(lhs); nodes.insert(rhs); solved = false; }

   void AddAssignmentRelationship(Variable lhs, Variable rhs) { copies.insert({rhs, lhs}); nodes.insert(lhs); nodes.insert(rhs); solved = false; }

   void AddLoadRelationship(Variable lhs, Variable ptr) { loads.insert({lhs, ptr}); nodes.insert(lhs); nodes.insert(ptr); solved = false; }

   void AddStoreRelationship(Variable ptr, Variable rhs) { stores.insert({ptr, rhs}); nodes.insert(ptr); nodes.insert(rhs); solved = false; }

   void Print() {
      Map();
      std::cout << "_____________________________________________________" << std::endl << std::endl;
      for (auto &x : pointsto) {
         if (x.first.kind == "tmp" || x.second.empty()) continue;
         std::cout << x.first.linenumber << " - " << x.first.nameoftype << (x.first.isPointer ? " * " : " & ") << x.first << std::endl << std::endl;
         for (auto &y : x.second)
            std::cout << y.linenumber << " - " << y.nameoftype << " " << y << " " << std::endl;
         std::cout << "_____________________________________________________" << std::endl << std::endl;
      }
   }

   // one line per points-to fact: file, line, name and kind of the pointer, then of the object. With maxPointers
   // > 0, objects that more declared variables point to are left out (shared hubs such as a context struct)
   int maxPointers = 0;

   void PrintTSV() {
      Finalize();
      std::vector<int> reach(vars_.size(), 0);
      if (maxPointers > 0)
         for (std::size_t i = 0; i < vars_.size(); ++i)
            if (vars_[i].kind == "var")
               for (int o : pts_[i]) ++reach[o];
      std::string out;
      for (std::size_t i = 0; i < vars_.size(); ++i) {
         const Variable &x = vars_[i];
         if (x.kind == "tmp" || pts_[i].empty()) continue;
         for (int o : pts_[i]) {
            if (maxPointers > 0 && reach[o] > maxPointers) continue;
            const Variable &y = vars_[o];
            out += x.filename; out += '\t'; out += std::to_string(x.linenumber); out += '\t'; out += x.nameofidentifier;
            out += '\t'; out += x.kind; out += '\t'; out += y.filename; out += '\t'; out += std::to_string(y.linenumber);
            out += '\t'; out += y.nameofidentifier; out += '\t'; out += y.kind; out += '\n';
         }
      }
      std::cout << out;
   }

   void PrintGraphViz() {
      Map();
      std::cout << "digraph pointers {\n";
      for (auto &x : pointsto) {
         if (x.first.kind == "tmp") continue;
         for (auto &y : x.second)
            std::cout << "   \"" << x.first << "\" -> \"" << y << "\" \n";
      }
      std::cout << "}";
   }

   std::vector<Variable> GetPointsTo(Variable ptr) {
      Map();
      std::vector<Variable> result(pointsto[ptr].begin(), pointsto[ptr].end());
      return result;
   }

   std::vector<Variable> GetPointers() {
      Map();
      std::vector<Variable> pointers;
      for (auto &x : pointsto)
         if (!x.second.empty() && x.first.kind != "tmp")
            pointers.push_back(x.first);
      return pointers;
   }

   srcPtrAndersen *Clone() const {
      return (new srcPtrAndersen(*this));
   }

   void Finalize() {
      if (solved) return;
      // worklist solver with difference propagation over integer ids
      std::map<Variable, int> id;
      std::vector<Variable> var;
      auto idOf = [&](const Variable &v) {
         auto it = id.find(v);
         if (it != id.end()) return it->second;
         int n = (int)var.size(); id[v] = n; var.push_back(v); return n;
      };
      for (auto &v : nodes) idOf(v);
      for (auto &b : base) for (auto &o : b.second) idOf(o);
      std::size_t N = var.size();
      std::vector<std::set<int>> pts(N), delta(N), succ(N);
      std::vector<std::vector<int>> loadsOf(N), storesOf(N);   // loadsOf[p]: dsts of q = *p; storesOf[p]: srcs of *p = q
      for (auto &b : base) { int p = idOf(b.first); for (auto &o : b.second) { int oi = idOf(o); if (pts[p].insert(oi).second) delta[p].insert(oi); } }
      for (auto &c : copies) succ[idOf(c.first)].insert(idOf(c.second));
      for (auto &l : loads) loadsOf[idOf(l.second)].push_back(idOf(l.first));
      for (auto &st : stores) storesOf[idOf(st.first)].push_back(idOf(st.second));
      pts.resize(var.size()); delta.resize(var.size()); succ.resize(var.size());
      loadsOf.resize(var.size()); storesOf.resize(var.size());
      std::vector<int> work; std::vector<char> queued(var.size(), 0);
      for (std::size_t i = 0; i < var.size(); ++i) if (!delta[i].empty()) { work.push_back((int)i); queued[i] = 1; }
      auto addEdge = [&](int from, int to) {
         if (!succ[from].insert(to).second) return;
         std::size_t before = pts[to].size();
         for (int o : pts[from]) if (pts[to].insert(o).second) delta[to].insert(o);
         if (pts[to].size() != before && !queued[to]) { work.push_back(to); queued[to] = 1; }
      };
      while (!work.empty()) {
         int n = work.back(); work.pop_back(); queued[n] = 0;
         std::set<int> d; d.swap(delta[n]);
         if (d.empty()) continue;
         for (int o : d) {                        // new objects n points to: complex constraints
            for (int dst : loadsOf[n]) addEdge(o, dst);
            for (int src : storesOf[n]) addEdge(src, o);
         }
         for (int m : std::vector<int>(succ[n].begin(), succ[n].end())) {
            bool grew = false;
            for (int o : d) if (pts[m].insert(o).second) { delta[m].insert(o); grew = true; }
            if (grew && !queued[m]) { work.push_back(m); queued[m] = 1; }
         }
      }
      vars_ = std::move(var);
      pts_ = std::move(pts);
      pointsto.clear();
      mapped = false;
      solved = true;
   }

   // the Variable-keyed map, built only for Print, GraphViz and the getters (TSV prints from the ids)
   void Map() {
      Finalize();
      if (mapped) return;
      for (std::size_t i = 0; i < vars_.size(); ++i)
         for (int o : pts_[i]) pointsto[vars_[i]].insert(vars_[o]);
      mapped = true;
   }

private:
   bool solved = false, mapped = false;
   std::vector<Variable> vars_;
   std::vector<std::set<int>> pts_;
   std::set<Variable> nodes;
   std::map<Variable, std::set<Variable>> base;
   std::set<std::pair<Variable, Variable>> copies, loads, stores;
   std::map<Variable, std::set<Variable>> pointsto;
};


class srcPtrSteensgaard {
public:
   ~srcPtrSteensgaard() { };

   // loads and stores are not modeled by this unification-based variant; use Andersen (-a) for them
   void AddLoadRelationship(Variable lhs, Variable ptr) { }

   void AddStoreRelationship(Variable ptr, Variable rhs) { }

   int maxPointers = 0;
   void PrintTSV() { Print(); }

   void AddPointsToRelationship(Variable lhs, Variable rhs) {
      ds.MakeSet(rhs);
      if (pointsTo[lhs].empty()) {
         pointsTo[lhs] = rhs;
      }
      else {
         ds.Union(pointsTo[lhs], rhs);
      }
   }

   void AddAssignmentRelationship(Variable lhs, Variable rhs) {
      if (pointsTo[lhs].empty())
         pointsTo[lhs] = pointsTo[rhs];
      else if (pointsTo[rhs].empty())
         pointsTo[rhs] = pointsTo[lhs];
      else
         ds.Union(pointsTo[lhs], pointsTo[rhs]); 
   }

   void Print() {
      std::vector<Variable> pointers = GetPointers();

      for(auto it = pointers.begin(); it != pointers.end(); ++it) {
         std::cout << *it << std::endl; 

         std::vector<Variable> pointsTo = GetPointsTo(*it);
         for(auto it2 = pointsTo.begin(); it2 != pointsTo.end(); ++it2) 
            std::cout << *it2 << std::endl;

         std::cout << "_____________________________________" << std::endl << std::endl;
      } 
   }

   void PrintGraphViz() {
   
   }

   std::vector<Variable> GetPointsTo(Variable ptr) { 
      std::list<Variable> pointedTo = ds.GetSet(pointsTo[ptr]);

      std::vector<Variable> result;

      for(auto it = pointedTo.begin(); it != pointedTo.end(); ++it) {
         result.push_back(*it);
      }

      return result;
   }

   std::vector<Variable> GetPointers() {
      std::vector<Variable> pointers;

      for(auto it = pointsTo.begin(); it != pointsTo.end(); ++it) {
         pointers.push_back(it->first);
      } 

      return pointers;
   }

   srcPtrSteensgaard *Clone() const {
      return (new srcPtrSteensgaard(*this));
   }

private:
   DisjointSet ds;
   std::map<Variable, Variable> pointsTo;
};

#endif

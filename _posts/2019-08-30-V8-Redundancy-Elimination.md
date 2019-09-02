---
layout: post
title:  "Redundancy Elimination Reducer in V8 and 34C3 CTF V9"
date:   2019-08-28 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

`RedundancyElimination` reducer is used to remove nodes that are not necessary, such as redundant `kCheckXXX` node. For example, if there is already a `kCheckXXX` before another `kCheckXXX`, the later `kCheckXXX` may be removed if we are sure this check will never be violated. However, if this assumption is wrong, vulnerability may arise. `V9` in 34C3 CTF is an example for this.

## 0x01 Search

As I covered in previous [articles](https://mem2019.github.io/jekyll/update/2019/08/28/V8-GraphReducer-Notes.html), `GraphReducer` reduces the graph using depth-first-search, starting from `End` node. However, when we tries to reduce a redundant node, we may need to have the information about its input effect nodes (e.i. nodes before), which we cannot have if we search the graph from `End` node.

Therefore, the approach this reducer applies is to do nothing until `Start` node is reached, and use the revisit trick to perform search again starting from `Start`, and this time we will have the information about input effect nodes.

Here is the `Reduce` function of `RedundancyElimination`:

```c++
Reduction RedundancyElimination::Reduce(Node* node) {
  if (node_checks_.Get(node)) return NoChange();
  switch (node->opcode()) {
    case IrOpcode::kCheckBigInt:
    case IrOpcode::kCheckBounds:
    case IrOpcode::kCheckEqualsInternalizedString:
    /* ... other check nodes ... */
      return ReduceCheckNode(node);
    /* ... some other nodes handling ... */
    case IrOpcode::kStart:
      return ReduceStart(node);
  }
  return NoChange();
}
```

The `ReduceCheckNode` is the one that I am going to focus on. Let's put the conclusion first, field `node_checks_` is used to record all effect input predecessor nodes of every node. `node_checks_.Get` is used to map a node to all of its effect input predecessors, using `nodeid` as index to a vector. `EffectPathChecks` is essentially a linked-list of `Node*` pointers. 

```c++
Reduction RedundancyElimination::ReduceCheckNode(Node* node) {
  Node* const effect = NodeProperties::GetEffectInput(node);
  EffectPathChecks const* checks = node_checks_.Get(effect);
  // If we do not know anything about the predecessor, do not propagate just yet
  // because we will have to recompute anyway once we compute the predecessor.
  if (checks == nullptr) return NoChange();
  // See if we have another check that dominates us.
  if (Node* check = checks->LookupCheck(node)) {
    ReplaceWithValue(node, check);
    return Replace(check);
  }

  // Learn from this check.
  return UpdateChecks(node, checks->AddCheck(zone(), node));
}
```

Initially, everything is empty, so `node_checks_.Get` will just return `nullptr`, so `ReduceCheckNode` will just return `NoChange()`. This always holds until `Start` node is reached.

```c++
Reduction RedundancyElimination::ReduceStart(Node* node) {
  return UpdateChecks(node, EffectPathChecks::Empty(zone()));
}
```

`UpdateChecks` essentially calls `node_checks_.Set(node, checks)` to update the `checks` of given node, but this is only done when new `checks` is different from original one. Also, if there is any change, return `Changed(node)` as `Reduction`.

```c++
Reduction RedundancyElimination::UpdateChecks(Node* node,
                                              EffectPathChecks const* checks) {
  EffectPathChecks const* original = node_checks_.Get(node);
  // Only signal that the {node} has Changed, if the information about {checks}
  // has changed wrt. the {original}.
  if (checks != original) {
    if (original == nullptr || !checks->Equals(original)) {
      node_checks_.Set(node, checks);
      return Changed(node);
    }
  }
  return NoChange();
}
```

Therefore, after reducing `Start` node, the result of reduction will be a in-place replacement. Remember, if the result is in-place replacement, all use nodes will be revisited again.

```c++
// GraphReducer::ReduceTop
// Check if we have a new replacement.
if (replacement != node) {
  Replace(node, replacement, max_id);
} else {
  // Revisit all uses of the node.
  for (Node* const user : node->uses()) {
    // Don't revisit this node if it refers to itself.
    if (user != node) Revisit(user);
  }
}
```

Thus the use nodes will be visited again, but this time effect input `node_checks_.Get(effect)` does not return `nullptr` but `UpdateChecks(node, checks->AddCheck(zone(), node))`. 

`AddCheck` simply add the node to the linked-list, and return the newly created `EffectPathChecks`, defined as below.

```c++
RedundancyElimination::EffectPathChecks const*
RedundancyElimination::EffectPathChecks::AddCheck(Zone* zone,
                                                  Node* node) const {
  Check* head = new (zone->New(sizeof(Check))) Check(node, head_);
  return new (zone->New(sizeof(EffectPathChecks)))
      EffectPathChecks(head, size_ + 1);
}
```

This means `EffectPathChecks` of a node stores itself plus `EffectPathChecks` of its effect node, and base case is `Start` node whose `EffectPathChecks` is empty. In other words, it stores all previous nodes on the effect input chain, including itself but except `Start` node. Note that this is only the case if there are `kCheckXXX` nodes only, for other kinds of nodes, things might be different. // this might be inaccurate?

Then, since `UpdateChecks` which adds a new node always returns `Changed(node)`, all use nodes of this node (one of the use nodes of `Start` node) will also be pushed into revisit queue. I would say this is a bit similar to BFS starting from `Start` node, but in reality things might not work in this way because there are also other reducers and because DFS is also still ongoing.

## 0x02 Eliminate the Redundancy

There is a piece of code in `ReduceCheckNode` that I have not discussed yet.

```c++
// See if we have another check that dominates us.
if (Node* check = checks->LookupCheck(node)) {
  ReplaceWithValue(node, check); 
  // remove node, use check new value node
  return Replace(check);
  // identical to `return Reduction(check)`
  // nothing will be done in GraphReducer::Replace later on
  // because node has been removed,
  // and it has no use nodes
}
```

The intuition of this is to check whether `node` can be covered by previous input effect nodes, and if so, remove this node, because we know it is redundant.

`LookupCheck` iterates over the list stored in `checks`, which stores effect predecessor nodes. If one of the predecessor nodes subsumes the given node, return it.

```c++
Node* RedundancyElimination::EffectPathChecks::LookupCheck(Node* node) const {
  for (Check const* check = head_; check != nullptr; check = check->next) {
    if (CheckSubsumes(check->node, node) && TypeSubsumes(node, check->node)) {
      DCHECK(!check->node->IsDead());
      return check->node;
    }
  }
  return nullptr;
}

// Does check {a} subsume check {b}?
bool CheckSubsumes(Node const* a, Node const* b) {
  if (a->op() != b->op()) {
    if (a->opcode() == IrOpcode::kCheckInternalizedString &&
        b->opcode() == IrOpcode::kCheckString) {
      // CheckInternalizedString(node) implies CheckString(node)
    } else if (a->opcode() == IrOpcode::kCheckSmi &&
               b->opcode() == IrOpcode::kCheckNumber) {
      // CheckSmi(node) implies CheckNumber(node)
    }  /* ... some other else-if checks ... */
      else if (a->opcode() != b->opcode()) {
      return false;
    } else {
      switch (a->opcode()) {
        case IrOpcode::kCheckBounds:
        case IrOpcode::kCheckSmi:
        case IrOpcode::kCheckString:
        case IrOpcode::kCheckNumber:
        case IrOpcode::kCheckBigInt:
          break;
        /* ... other cases ... */
      }
    }
  } // check if opcode of a could subsume opcode of b
  for (int i = a->op()->ValueInputCount(); --i >= 0;) {
    if (a->InputAt(i) != b->InputAt(i)) return false;
  } // check that inputs are identical
  return true;
}
```

## 0x03 V9

[V9](https://github.com/saelo/v9) is a challenge from `34C3 CTF`, the patch I am going to use here is [v9_7.2.patch](https://github.com/saelo/v9/blob/master/v9_7.2.patch). 

### Root Cause

In the patch, `case IrOpcode::kCheckMaps:` is added to `Reduce` function, so that for this opcode, `ReduceCheckNode` will be called, and a piece of codes is added to `CheckSubsumes` function.

```c++
case IrOpcode::kCheckMaps: {
    // CheckMaps are compatible if the first checks a subset of the second.
    ZoneHandleSet<Map> const& a_maps = CheckMapsParametersOf(a->op()).maps();
    ZoneHandleSet<Map> const& b_maps = CheckMapsParametersOf(b->op()).maps();
    if (!b_maps.contains(a_maps)) {
        return false;
    } // TODO: investigate CheckMapsParametersOf and ZoneHandleSet<Map>
    break;
}
```

What this does is essentially check if `kCheckMaps b` includes `kCheckMaps a`, if so we don't need the `b` because it thinks `b` must hold as long as `a` holds. However, the problem is map of object can actually change during the execution, so even if it could satisfy `a` before, it does not have to satisfy `b` later on. Thus the assumption is wrong, and using this we can have type confusion.

let's see how this function is reduced by `RedundancyElimination`.

```javascript
function f(o, g)
{
    const x = o.x;// = 0xdead;
    g();
    o.d = 0x2000;
}
for (var i = 0; i < 0x1000; i++)
{
    f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>1);
    f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>2);
    f({x:1,y:2,z:3,l:4,a:5,b:6,c:7,d:8,e:9}, ()=>3);
}
```

Since the first phase that use `RedundancyElimination` is `LoadElimination`, we can look at `LoopPeeling` to see the graph before `RedundancyElimination`.

// pic

As we can see, there are 2 `CheckMaps` nodes. Node 34 is effect input of `LoadField[+24]`, and node 37 is effect input of `StoreField[+80]`.

After `LoadElimination` phase, the second `CheckMaps` disappears, so `StoreField[+80]` is executed without checking, which is problematic.

//pic

This is also clear if we look at assembly generated.

```assembly
call r10 ; call g()
REX.W movq rax,0x200000000000
REX.W movq rbx,[rbp+0x18] ; load object pointer
REX.W movq [rbx+0x4f],rax ; write to +0x50 field
; clearly there is no check
```

### Exploitation

In function `g()`, if we can shrink the size of  `obj`, we can have a out-of-bound write. The idea is to put an array there so that we can rewrite its length field, which gives an array with OOB access.
 Now the exploitation becomes regular: use a signature array to leak web assembly function address and use`ArrayBuffer` to achieve arbitrary R&W.

The difference is, after shrinking size of `obj`, positions that is originally used to store fields will be filled with `FILLER_TYPE` objects, and it is useless to rewrite these things. Therefore, we need to invoke garbage collection so that these offsets will store interesting data.

Full exploit with comments is [here](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/v9.js).



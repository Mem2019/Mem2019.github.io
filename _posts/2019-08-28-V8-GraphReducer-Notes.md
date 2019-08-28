---
layout: post
title:  "Notes about GraphReducer in V8"
date:   2019-08-28 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview
`GraphReducer` is a class that performs reduction in template method pattern given a list of different reducers. It is used in this way, for example:

```c++
// pipeline.cc
struct TypedLoweringPhase {
  static const char* phase_name() { return "V8.TFTypedLowering"; }

  void Run(PipelineData* data, Zone* temp_zone) {
    GraphReducer graph_reducer(temp_zone, data->graph(),
                               &data->info()->tick_counter(),
                               data->jsgraph()->Dead());
    DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                              data->common(), temp_zone);
    JSCreateLowering create_lowering(&graph_reducer, data->dependencies(),
                                     data->jsgraph(), data->broker(),
                                     temp_zone);
    /* ... some other reducers ... */
    AddReducer(data, &graph_reducer, &dead_code_elimination);
    AddReducer(data, &graph_reducer, &create_lowering);
    /* ... some other reducers ... */
    graph_reducer.ReduceGraph();
  }
};
```

Function `AddReducer` essentially calls `graph_reducer.AddReducer`, and `graph_reducer.ReduceGraph` is the function that actually performs the reduction, using `Reduce` virtual function implemented by each reducer.

The base class of every reducer, like `DeadCodeElimination` and `JSCreateLowering` shown here, is `Reducer`, defined as below:

```c++
class V8_EXPORT_PRIVATE Reducer {
 public:
  virtual ~Reducer() = default;

  // Only used for tracing, when using the --trace_turbo_reduction flag.
  virtual const char* reducer_name() const = 0;

  // Try to reduce a node if possible.
  virtual Reduction Reduce(Node* node) = 0;

  // Invoked by the {GraphReducer} when all nodes are done.  Can be used to
  // do additional reductions at the end, which in turn can cause a new round
  // of reductions.
  virtual void Finalize();

  /* ... some static functions ...*/
};
```

Clearly, `Reduce` is the pure virtual function that every concrete reducer needs to implement.

## 0x01 GraphReducer Overview

### Fields

These are some important fields of `GraphReducer`.

```c++
// graph-reducer.h
Graph* const graph_; // the graph to be reduced, passed into constructor
Node* const dead_; // TODO
NodeMarker<State> state_; // state recorder of each nodes, covered later
ZoneVector<Reducer*> reducers_; // reducers passed into AddReducer
ZoneQueue<Node*> revisit_; // nodes to be revisit, detailed later
ZoneStack<NodeState> stack_; // stack used for DFS, detailed later
TickCounter* const tick_counter_; // TODO
```

`ZoneVector`, `ZoneQueue` and `ZoneStack` are simply `std::vector`, `std::queue` and `std::stack`, but instead of using `std::allocator`, the `ZoneAllocator` is used, which allocates memory using a memory allocation implemented by V8 instead of using system heap directly.

### State

Field `state_` is used to record state of each node, the `State` is an `enum` defined as below.

```c++
enum class GraphReducer::State : uint8_t {
  kUnvisited, // the node is not visited yet
  kRevisit, // the node should be revisited again
  kOnStack, // the node is currently on DFS stack
  kVisited // the node has already been visited
};
```

### NodeState

`NodeState` is a helper structure used for DFS.

```c++
struct NodeState {
  Node* node;
  int input_index;
};
```

`input_index` represents the index of next `input` node to be traversed, discussed later.

### Methods

There are some simple utility methods in this class.

```c++
// push the nodes into DFS stack
void GraphReducer::Push(Node* const node) {
  DCHECK_NE(State::kOnStack, state_.Get(node));
  state_.Set(node, State::kOnStack); // set state of node as kOnStack
  stack_.push({node, 0}); 
  // push it into nodes, input_index is 0 initially
  // which means start traversing its input nodes at beginning
}

void GraphReducer::Pop() {
  Node* node = stack_.top().node; // peek top node
  state_.Set(node, State::kVisited); // set state of node as kVisited
  stack_.pop(); // pop
}

// this is called when we try to recurse on a input node
bool GraphReducer::Recurse(Node* node) {
  if (state_.Get(node) > State::kRevisit) return false;
  // if node state is kOnStack or kVisited
  // we don't recurse, and return false
  Push(node);
  return true;
  // otherwise, we push the node into DFS stack to recurse on it
  // and return true
}

void GraphReducer::Revisit(Node* node) {
  if (state_.Get(node) == State::kVisited) {
    state_.Set(node, State::kRevisit);
    revisit_.push(node);
  }
  // if the node has been visited
  // set it as kRevisit, 
  // and push it into revisit queue
}
```

## 0x02 ReduceNode

The `ReduceGraph` function, which is used by `Run` functions of different kinds of phases, is implemented as below.

```c++
void GraphReducer::ReduceGraph() { ReduceNode(graph()->end()); }
```

`graph()->end()` returns the `End` node that you always see in turbolizer graph. `ReduceNode` is the function that perform actual reduction.

```c++
void GraphReducer::ReduceNode(Node* node) {
  DCHECK(stack_.empty());
  DCHECK(revisit_.empty());
  Push(node);
  for (;;) {
    if (!stack_.empty()) {
      // Process the node on the top of the stack, potentially pushing more or
      // popping the node off the stack.
      ReduceTop();
    } else if (!revisit_.empty()) {
      /* ... */
    } else {
      /* ... */
    }
  }
  DCHECK(revisit_.empty());
  DCHECK(stack_.empty());
}
```

For the first time of the loop, stack is not empty, so `ReduceTop` is called. Also, until stack becomes empty, it will always call `ReduceTop`. In other word, it will fall into `else if` and `else` branch only after first DFS of the graph is done.

Then here is implementation of `ReduceTop`.

```c++
void GraphReducer::ReduceTop() {
  NodeState& entry = stack_.top();
  Node* node = entry.node; // peek the top node
  DCHECK_EQ(State::kOnStack, state_.Get(node));

  if (node->IsDead()) return Pop();  // Node was killed while on stack.

  Node::Inputs node_inputs = node->inputs();

  // Recurse on an input if necessary.
  int start = entry.input_index < node_inputs.count() ? entry.input_index : 0;
  // iterate input nodes from start
  // entry.input_index is 0 for the first time reduction of this node
  for (int i = start; i < node_inputs.count(); ++i) {
    Node* input = node_inputs[i];
    if (input != node && Recurse(input)) {
      // if recurse is true,
      // modify input_index to next input node to be traversed,
      // and return immediately.
      // ReduceTop will be called again in next for(;;) loop,
      // but this time top node becomes
      // the input node being just pushed in Recurse function,
      // which is the node that we want to recurse.
      // in this way DFS is implemented without any real recursion.
      entry.input_index = i + 1;
      return;
    }
  }
  for (int i = 0; i < start; ++i) {
    Node* input = node_inputs[i];
    if (input != node && Recurse(input)) {
      // recurse previous input nodes
      // I _think_ is because 
      // previous input nodes may be modified by reducer 
      // so re-iterate is necessary
      // for those that are already reduced
      // state will be kVisited so Recurse will simply return false
      entry.input_index = i + 1;
      return;
    }
  }

  /* If there is no input node to be recursed, reduce on this node */
  /* which is exactly depth-first-search */

  // Remember the max node id before reduction.
  NodeId const max_id = static_cast<NodeId>(graph()->NodeCount() - 1);

  // All inputs should be visited or on stack. Apply reductions to node.
  Reduction reduction = Reduce(node);

  // If there was no reduction, pop {node} and continue.
  if (!reduction.Changed()) return Pop();

  // Check if the reduction is an in-place update of the {node}.
  Node* const replacement = reduction.replacement();
  if (replacement == node) {
    // In-place update of {node}, may need to recurse on an input.
    Node::Inputs node_inputs = node->inputs();
    // try to recurse on input again
    // I _think_ it is because in-place may modify input nodes
    // so another recusion is needed
    for (int i = 0; i < node_inputs.count(); ++i) {
      Node* input = node_inputs[i];
      if (input != node && Recurse(input)) {
        entry.input_index = i + 1;
        return;
      }
    }
  }

  // After reducing the node, pop it off the stack.
  Pop();

  // Check if we have a new replacement.
  if (replacement != node) {
    Replace(node, replacement, max_id); // detailed later
  } else {
    // Revisit all uses of the node.
    // for in-place replacement
    for (Node* const user : node->uses()) {
      // Don't revisit this node if it refers to itself.
      if (user != node) Revisit(user);
    }
  }
}
```

## 0x02 Reduce

`Reduce` is the function that perform the actual reduction on a specific node using provided reducers.

```c++
Reduction GraphReducer::Reduce(Node* const node) {
  auto skip = reducers_.end();
  for (auto i = reducers_.begin(); i != reducers_.end();) {
    if (i != skip) {
      tick_counter_->DoTick();
      Reduction reduction = (*i)->Reduce(node); // Reducer::Reduce
      if (!reduction.Changed()) {
        // No change from this reducer.
      } else if (reduction.replacement() == node) {
        // {replacement} == {node} represents an in-place reduction. Rerun
        // all the other reducers for this node, as now there may be more
        // opportunities for reduction.
        /* ... codes for trace turbo ... */
        skip = i; 
        // skip the index that produces the in-place
        // because when the loop reruns
        // and all previous reducers have no change
        // it must be pointless to run this reduction again
        // since it must have no effect
        i = reducers_.begin();
        continue;
      } else {
        // {node} was replaced by another node.
        /* ... codes for trace turbo ... */
        return reduction; // return if there is replacement
      }
    }
    ++i;
  }
  if (skip == reducers_.end()) {
    // No change from any reducer.
    return Reducer::NoChange();
  }
  // At least one reducer did some in-place reduction.
  return Reducer::Changed(node);
}
```

This function tries to reduce the given node using all of the reducers. _From my perspective_, this function tries its best to obtain a non-in-place reduction, and return directly the corresponding reduction as long as such reduction is found. If there is no reduction at all, `Reducer::NoChange` will be returned. If there is only one or more in-place reduction, `Reducer::Changed(node)` will be returned.

Class `Reduction` is pretty simple.

```c++
// Represents the result of trying to reduce a node in the graph.
class Reduction final {
 public:
  explicit Reduction(Node* replacement = nullptr) : replacement_(replacement) {}

  Node* replacement() const { return replacement_; }
  bool Changed() const { return replacement() != nullptr; }

 private:
  Node* replacement_;
};
```

So do some static method of `Reducer`.

```c++
// Helper functions for subclasses to produce reductions for a node.
static Reduction NoChange() { return Reduction(); }
static Reduction Replace(Node* node) { return Reduction(node); }
static Reduction Changed(Node* node) { return Reduction(node); }
```

## 0x03 Replace

Function `Replace`, as its name suggests, is used to replace a node with another node.

```c++
void GraphReducer::Replace(Node* node, Node* replacement, NodeId max_id) {
  if (node == graph()->start()) graph()->SetStart(replacement);
  if (node == graph()->end()) graph()->SetEnd(replacement);
  if (replacement->id() <= max_id) {
    // {replacement} is an old node, so unlink {node} and assume that
    // {replacement} was already reduced and finish.
    for (Edge edge : node->use_edges()) {
      Node* const user = edge.from();
      Verifier::VerifyEdgeInputReplacement(edge, replacement);
      edge.UpdateTo(replacement);
      // Don't revisit this node if it refers to itself.
      if (user != node) Revisit(user);
    }
    node->Kill();
  } else {
    // Replace all old uses of {node} with {replacement}, but allow new nodes
    // created by this reduction to use {node}.
    for (Edge edge : node->use_edges()) {
      Node* const user = edge.from();
      if (user->id() <= max_id) {
        edge.UpdateTo(replacement);
        // Don't revisit this node if it refers to itself.
        if (user != node) Revisit(user);
      }
    }
    // Unlink {node} if it's no longer used.
    if (node->uses().empty()) node->Kill();

    // If there was a replacement, reduce it after popping {node}.
    Recurse(replacement);
  }
}
```

There are 2 cases, when `replacement` is an old node or when `replacement` is a new node. For both of them, general idea is same, iterate over all nodes that use the node, and replace and revisit the node. However, there are some differences.

1. For old node case, replacement is always done; for new node case, replacement is only done when user is old node.
2. For old node case, node is always killed after replacement loop; for new node case, node is only killed when it is empty.
3. For new node case, `Recurse` is called on `replacement`.

I am not completely clear why the algorithm works like this, so I will not discuss too much about it.

Function `UpdateTo` is defined in this way. As the code shown, not only nodes stored in edge is updated, but information stored in old node and new node are also updated. TODO: investigate `Edge` in more detail.

```c++
void UpdateTo(Node* new_to) {
  Node* old_to = *input_ptr_;
  if (old_to != new_to) {
  // update only if new_to is different
    if (old_to) old_to->RemoveUse(use_);
    // remove connection from old_to to use_
    *input_ptr_ = new_to;
    // update input_ptr_ of the edge
    if (new_to) new_to->AppendUse(use_);
    // add connection from new_to to use_
  }
}
```

 ## 0x04 Revisit

Let's go back to `ReduceNode` again.

```c++
void GraphReducer::ReduceNode(Node* node) {
  DCHECK(stack_.empty());
  DCHECK(revisit_.empty());
  Push(node);
  for (;;) {
    if (!stack_.empty()) {
      /* ... ReduceTop invistigated before ... */
    } else if (!revisit_.empty()) {
      // If the stack becomes empty, revisit any nodes in the revisit queue.
      // this is executed only if all nodes in graph are reduced once
      Node* const node = revisit_.front();
      revisit_.pop();
      if (state_.Get(node) == State::kRevisit) {
        // state can change while in queue.
        Push(node); 
        // push the node to be revisted to stack
        // so ReduceTop will be called on this node in next iteration
      }
    } else {
      // Run all finalizers.
      for (Reducer* const reducer : reducers_) reducer->Finalize();
      // TODO: investigate this in more detial
      // Check if we have new nodes to revisit.
      if (revisit_.empty()) break; 
      // it seems that finalizer may add revisit queue
      // so if it is not empty, reduction should continue
    }
  }
  DCHECK(revisit_.empty());
  DCHECK(stack_.empty());
}
```


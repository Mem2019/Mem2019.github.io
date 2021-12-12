---
layout: post
title:  "AFLGO Source Code Analysis: Graph Construction and Distance Calculation"
date:   2021-11-06 00:00:00 +0000
categories: jekyll update
---

## 0x00 Introduction

[AFLGO](https://mboehme.github.io/paper/CCS17.pdf) is a modification of AFL that perform *directed fuzzing*, for more information, please read the [paper](https://mboehme.github.io/paper/CCS17.pdf). In this article, I will analyze source code of AFLGO that constructs call graph and control flow graphs of given program to be fuzzed and uses these graphs to calculate distance from each block to target locations. Most of these works are implemented in `afl-llvm-pass.so.cc` and `distance_calculator/main.cpp`. The analysis is based on commit `154cf6f84951ee5099732e267d1e7c79c233f278`, in case if author might change the code in the future.

## 0x01 Two Stages of Compilation

When we are using AFLGO, unlike AFL by using which we only need to compile the target binary with `afl-*` compiler for *once*, we need to compile the target binary *twice*. The first compilation is in order to analyze the program to generate information (e.g. control flow graphs) needed for computing distances; the second compilation is the actual instrumentation that generates binary to be fuzzed.

This is clearly illustrated in function `AFLCoverage::runOnModule` at `afl-llvm-pass.so.cc`: if `TargetsFile` is set, then analysis step is performed; if `DistanceFile` is set, then instrumentation step is performed. For analysis step, we also need to set an `OutDirectory` to output results of analysis.

### Generation of  Information

When compiling for analysis, variable `is_aflgo_preprocessing` is set to `true`, and the execution goes into `if (is_aflgo_preprocessing)` branch. In this branch, all functions except ones in `Blacklist` is iterated; all blocks in these functions and all instructions in each of these blocks are also iterated just like what a `llvm` pass usually does, except instructions from external libraries starting with `"/usr/"`. Part of source code is shown below.

```c++
for (auto &F : M) {

  bool has_BBs = false;
  std::string funcName = F.getName().str();

  /* Black list of function names */
  if (isBlacklisted(&F)) {
    continue;
  }

  bool is_target = false;
  for (auto &BB : F) {

    std::string bb_name("");
    std::string filename;
    unsigned line;

    for (auto &I : BB) {
      getDebugLoc(&I, filename, line);

      /* Don't worry about external libs */
      static const std::string Xlibs("/usr/");
      if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
        continue;
      
      // ...
```

Firstly, each block will be associated with a block name, `bb_name`, which is assigned to be `bb_name = filename + ":" + std::to_string(line)`, where `filename` and `line` are location associated with the *first instruction that has `DebugLoc`* of this block.

```c++
if (bb_name.empty()) {

  std::size_t found = filename.find_last_of("/\\");
  if (found != std::string::npos)
    filename = filename.substr(found + 1);

  bb_name = filename + ":" + std::to_string(line);
}
```

In addition, `filename` and `line` are compared against all target locations. If they match one of the target locations, `is_target` will be set to `true`. Such boolean variable is used to add all functions that contain target location to `Ftargets.txt`.

```c++
if (!is_target) {
    for (auto &target : targets) {
      std::size_t found = target.find_last_of("/\\");
      if (found != std::string::npos)
        target = target.substr(found + 1);

      std::size_t pos = target.find_last_of(":");
      std::string target_file = target.substr(0, pos);
      unsigned int target_line = atoi(target.substr(pos + 1).c_str());
      // parse the target location

      if (!target_file.compare(filename) && target_line == line)
        is_target = true;

    }
}
```

```c++
// If a function contains any target location, it will be recorded to Ftargets.txt 
if (is_target)
  ftargets << F.getName().str() << "\n";
```

It also extracts `CalledFunction` of `CallInst`, if any, and records a `bb_name` and function name pair into `BBcalls.txt`. This is used to map each basic block to all functions which it calls.

```c++
if (auto *c = dyn_cast<CallInst>(&I)) {

  std::size_t found = filename.find_last_of("/\\");
  if (found != std::string::npos)
    filename = filename.substr(found + 1);

  if (auto *CalledF = c->getCalledFunction()) {
    if (!isBlacklisted(CalledF))
      bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
  }
}
```

During iteration, all basic block names and function names are also recorded into `BBnames.txt` and `Fnames.txt` respectively. (`bbnames << BB.getName().str() << "\n";` and `fnames << F.getName().str() << "\n";`)

Control flow graph of each function is also recorded to `cfg.[funcName].dot` in `dot-files` directory using `WriteGraph(cfgFile, &F, true)` function in `llvm`.

```c++
std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
std::error_code EC;
raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
if (!EC) {
  WriteGraph(cfgFile, &F, true);
}
```

### Instrumentation

Using information collected above, for each basic block in binary, a distance to target locations will be calculated and stored in a file, which is passed via `DistanceFile` and used in instrumentation step. I will detail the way to calculate distances later.

The instrumentation step is comparatively simple. Compared to original AFL instrumentation, one more distance-related operation is added. As it iterates all basic blocks, it finds in the distance file whether current basic block has a distance value recorded. If so, the distance value is magnified by 100 and converted into integer, and used in instrumentation to be added to `shm[MAPSIZE]`. Also in instrumentation, `shm[MAPSIZE + (4 or 8)]` is incremented by one. In this way, when this basic block is executed in runtime, `shm[MAPSIZE]` will be added by its distance to target locations and `shm[MAPSIZE + (4 or 8)]` will be incremented by one.

```c
if (distance >= 0) { // if a distance is found

  ConstantInt *Distance =
      ConstantInt::get(LargestType, (unsigned) distance);

  /* Add distance to shm[MAPSIZE] */

  Value *MapDistPtr = IRB.CreateBitCast(
      IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
  LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
  MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
  IRB.CreateStore(IncrDist, MapDistPtr)
      ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  /* Increase count at shm[MAPSIZE + (4 or 8)] */

  Value *MapCntPtr = IRB.CreateBitCast(
      IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
  LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
  MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

  Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
  IRB.CreateStore(IncrCnt, MapCntPtr)
      ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

}
```

## 0x02 Calculating Distances

The distance generation is wrapped by a script `gen_distance_fast.py`. In this script, `construct_callgraph` function is called to first generate call graph from `llvm` `.bc` file. This is achieved by `llvm` built-in `-dot-callgraph` utility executed in function `opt_callgraph`. The result call graph for all binaries is finally stored at `callgraph.dot`.

Then `calculating_distances` function is called to execute `distance_calculator/main.cpp` for actual distance calculation. 

### Call Graph Distance

Firstly call graph distance is computed through executing `main.cpp` using function `exec_distance_prog`. `callgraph.dot`, `Ftargets.txt` and `Fnames.txt` are provided as input and `callgraph.distance.txt` is provided as output. These file paths are passed to `main.cpp` as arguments. In `main.cpp`, graph is processed using C++ boost library. I will not detail stuff about boost library here but core parts that calculate the distance, which starts at function `cg_calculation`.

This function accepts 2 arguments, first one is the boost graph representation that represents the call graph of the program, and second one is an array that stores all functions present in `Ftargets.txt`. What this function does is only map each target function name to actual nodes in type `vertex_desc`, and return these nodes.

```c++
std::vector<vertex_desc> cg_calculation(
    graph_t &G,
    std::ifstream &target_stream
) {
    cout << "Loading targets..\n";
    std::vector<vertex_desc> targets;
    for (std::string line; getline(target_stream, line); ) {
        bo::trim(line);
        for (auto t : find_nodes(G, line)) {
            targets.push_back(t);
        }
    }
    if (targets.empty()) {
        cout << "No targets available\n";
        exit(0);
    }
    return targets;
}
```

`find_node` is a function that maps vertex name to actual vertexes in the given graph.

```c++
std::vector<vertex_desc> ret;
bo::graph_traits<graph_t>::vertex_iterator vi, vi_end;
for (boost::tie(vi, vi_end) = vertices(G); vi != vi_end; ++vi) { // iterate all vertexes
    if(G[*vi].label.find(n_name) != std::string::npos) { 
        // if label of the vertex contains given name, push it to return array.
        // Note that n_name here is preprocessed with node_name,
        // so function name that is substring of another function name does not cause problem
        ret.push_back(*vi);
    }
}
```

Actually, I cannot come up with the case where 2 or more vertexes correspond to one name. (e.i. 2 or more functions in call graph have the same function name) However, for control flow graph later, this might be possible and will be covered later.

After `cg_calculation`, it iterates all vertexes represented by functions present in `Fname.txt`:

```c++
std::ifstream names = open_file(vm["names"].as<std::string>());
// ...
for (std::string line; getline(names, line); ) {
    bo::trim(line);
    distance(graph, line, targets, outstream, bb_distance);
}
```

Function `distance` is the actual function that calculates the distance. It firstly calculates `distances` using `init_distances_from`, which calculates shortest distances of all nodes from node `n`. Then call graph distances are calculated.

```c++
for (vertex_desc n : find_nodes(G, name)) {
    std::vector<int> distances(bo::num_vertices(G), 0);
    init_distances_from(G, n, distances);

    double d = 0.0;
    unsigned i = 0;
    if (is_cg) {
        for (vertex_desc t : targets) {
            auto shortest = distances[t];           // shortest distance from n to t
            if (shortest == 0 and n != t) continue; // only consider reachable targets
            d += 1.0 / (1.0 + static_cast<double>(shortest));
            ++i;
        }
    } else {
        // ...
    }
    double tmp = static_cast<double>(i) / d;
    if (d != 0 and (distance == -1 or distance > tmp)) {
        distance = tmp; // result is the minimum distance of all nodes
    }
}
```

According to code, formula for calculating the call graph distance for a node $$n$$ (which represents a function) is:

$$\large min_{n}\frac{|T_n|}{\sum_{t \in T_n} \frac{1}{1+S_{n\rightarrow t}}}$$

$$min_n$$ stands for we want to find the minimum value among all $$n$$ returned from `find_nodes`, but I think in call graph case there should be at most one vertex being returned; $$T_n$$ means set of all reachable targets from $$n$$; $$S_{n\rightarrow t}$$ means `distances[t]`, which is the minimum distance from $$n$$ to $$t$$.

### Basic Block Distance

After calculating call graph distances, the Python script then calls function `calculate_cfg_distance_from_file` for each `cfg.*.dot` file in `dot-files`, which represents control flow graph of each function. This function also calls `main.cpp`, but this time with `cfg.*.dot`, `BBtargets.txt`, `BBnames.txt`, `callgraph.distance.txt`(generated in last step) and `BBcalls.txt` as inputs, and `name + ".distances.txt"` as output. Note that this time the arguments passed are completely different from call graph case: call graph of program is replaced by control flow graph of each function; `Ftargets.txt` is replaced by `BBtargets.txt`; `Fnames.txt` is replaced by `BBnames.txt`.

Similarly, the distance calculation part starts with function `cfg_calculation`. Firstly, call graph distance file is converted into an `std::unordered_map` that maps function name to distance.

```c++
for (std::string line; getline(cg_distance_stream, line); ) {
    bo::trim(line);
    std::vector<std::string> splits;
    bo::algorithm::split(splits, line, bo::is_any_of(","));;
    assert(splits.size() == 2);
    cg_distance[splits[0]] = std::stod(splits[1]);
}
```

Also, for each basic block in control flow graph of current function, we collect all functions it calls using `BBcalls.txt`. Among these functions that have `cg_distance`, AFLGO get the minimum of these and set `bb_distance` to it.

```c++
for (std::string line; getline(cg_callsites_stream, line); ) {
    bo::trim(line);
    std::vector<std::string> splits;
    bo::algorithm::split(splits, line, bo::is_any_of(","));;
    assert(splits.size() == 2);
    if (not find_nodes(G, splits[0]).empty()) { 
    // only process basic blocks in current CFG
        if (cg_distance.find(splits[1]) != cg_distance.end()) {
        // only process called functions with `cg_distance`
            if (bb_distance.find(splits[0]) != bb_distance.end()) {
                if (bb_distance[splits[0]] > cg_distance[splits[1]]) {
                    bb_distance[splits[0]] = cg_distance[splits[1]];
                }
            } else {
                bb_distance[splits[0]] = cg_distance[splits[1]];
            }
            // get the minimum cg_distance of all functions called by a basic block
        }
    }
}
```

Finally, `bb_distance` of all target locations in current function is set to 0. However, I think this part is a bit problematic, because `BBtargets.txt` does not necessarily contain basic block name (e.i. It can be location of instruction other than first instruction of this basic block).

```c++
for (std::string line; getline(targets_stream, line); ) {
    bo::trim(line);
    std::vector<std::string> splits;
    bo::algorithm::split(splits, line, bo::is_any_of("/"));;
    size_t found = line.find_last_of('/');
    if (found != std::string::npos)
        line = line.substr(found+1);
    if (not find_nodes(G, splits[0]).empty()) {
        bb_distance[line] = 0.0;
        cout << "Added target BB " << line << "!\n";
    }
}
```

Then similar to call graph one, `distance` function is used to actually calculate the distance for each `line` in `names`. Note that here variable `names` is file `BBnames.txt` instead of `Fnames.txt`, which contains names of all basic blocks in the program. Firstly, if the basic block can be found in `bb_distance`, then the distance is simply `10` times its basic block distance.

```c++
if (not is_cg and bb_distance.find(name) != bb_distance.end()) {
    out << name << "," << bo::lexical_cast<std::string>(10 * bb_distance[name]) << "\n";
    return;
}
```

The other parts are same as the call graph distance calculation, except the `else` branch that is omitted last section. Another thing to note is that as mentioned before, it is possible for one basic block name to be mapped to multiple vertexes (e.i. `find_nodes` returns 2 or more elements). This can be caused by location in inline function.

```c++
for (auto &bb_d_entry : bb_distance) { // iterate each basic block name with bb_distance
    double di = 0.0;
    unsigned ii = 0;
    for (auto t : find_nodes(G, bb_d_entry.first)) { // iterate each basic block with this name
        auto shortest = distances[t];           // shortest distance from n to t
        if (shortest == 0 and n != t) continue; // not reachable
        di += 1.0 / (1.0 + 10 * bb_d_entry.second + static_cast<double>(shortest));
        ++ii;
    }
    if (ii != 0) {
        d += di / static_cast<double>(ii);
        ++i;
    }
}
```

The `for` loop iterate each basic block name with `bb_distance` (we will call them target basic blocks in following). Note that `bb_d_entry.first` that is not in current processing function is simply skipped, so only target basic blocks in current function is processed. Also, if all vertexes of a target basic block name in current function is not reachable by $$n$$, it will also be discarded.

For a target basic block name $$T$$, its distance $$D_{n\rightarrow T}$$ can be calculated as follows:

$$\large D_{n \rightarrow T} = \frac{\sum_{t \in V_n(T)} \frac{1}{1 + 10 D_{bb}(t) + S_{n \rightarrow t}}}{|V_n(T)|}$$

$$V_n(T)$$ means all basic block vertexes associated with basic block name $$T$$ that is reachable from starting node $$n$$; $$D_{bb}(t)$$ means `bb_distance` of basic block vertex $$t$$; $$S_{n \rightarrow t}$$ means the shortest distance from vertex $$n$$ to vertex $$t$$ in the control flow graph.

The final target distance of basic block $$n$$ is calculated as follows:

$$\large min_n \frac{|S_T|}{\sum_{T\in S_T} D_{n \rightarrow T}}$$

$$min_n$$ means we want the minimum distance among all vertexes returned from `find_node` (e.i. all vertexes with given basic block name); $$S_T$$ is the set of all names of target basic blocks reachable by $$n$$ in current processing function.

## 0x03 Others

As we can see, the actual implementation is a bit different from the one mentioned in paper, and this is the reason why I decides to investigate its source code.

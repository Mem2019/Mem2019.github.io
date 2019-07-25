---
layout: post
title:  "Fuzzilli Source Code Reading Notes"
date:   2019-07-24 00:00:00 +0000
categories: jekyll update
---

## 0x00 Introduction

[Fuzzilli](https://github.com/googleprojectzero/fuzzilli) is a open source JavaScript engine fuzzer developed by Google Project Zero. A custom JavaScript bytecode is designed and can be used to generate JavaScript source code (known as lifting). The fuzzer works by mutating such JavaScript bytecode, converting the byte code to JavaScript, and feeding the result JavaScript into JavaScript engine.

## 0x01 Bytecode

### Variable

Class `Variable` represents a variable in the bytecode, such as `v0` in `v0 <- LoadInt '0'`. It has a field `private let num: UInt16` which represent the id of the variable.

### Operation

Class `Operation` represents all possible kinds of operations in bytecode, and most of them can also correspond to particular JavaScript operation. It is a base class and specific operation is inherited from it. For example, the following code defines a `LoadString` operation:

```swift
// a = "qwer"
// v0 <− LoadString 'qwer'
class LoadString: Operation {
    let value: String
    
    init(value: String) {
        self.value = value
        super.init(numInputs: 0, numOutputs: 1, 
            attributes: [.isPrimitive, .isParametric, .isLiteral])
    }
}
```

Note that, the variable id is not stored into `Operation` instance, but constant is stored into `Operation`. For example, for instruction `v0 <− LoadString 'qwer'`, `'qwer'` is stored in field `value:String` of `LoadString`, but `v0` is not stored in `LoadString` instance but stored in `Instruction` instance. However, number of input variables, number of output variables and number of inner output variables are stored in `Operation` instance.

### Instruction

Class `Instruction` represent an actual instruction. It has a field `operation: Operation` which represents operation of this instruction, and also a field `inouts: [Variable]` which represents input variables, output variables and inner output variables.

### Program

Class `Program` represent a complete JavaScript program. It has a field `instructions: [Instruction]` which represent a list of `Instruction` instances.

### ProgramBuilder

Class `ProgramBuilder` is used to build a `Program` instance from scratch. This class is commonly used while mutating a `Program`.

**Adoption**

From my understanding, *adoption* is used by `ProramBuilder` to accept an instruction or variable(s) from another program, during which the id of variables are remapped to ensure the continuity.

```swift
public func beginAdoption(from program: Program) {
    varMaps.append([Variable: Variable]())
}
public func endAdoption() {
    varMaps.removeLast()
}

public func adopting(from program: Program, _ block: () -> Void) {
    beginAdoption(from: program)
    // push a empty [Variable: Variable] map into varMaps stack
    block()
    // execute the callback block passed into this function
    endAdoption()
    // pop from varMaps stack
}

/// Returns the next free variable.
private func nextVariable() -> Variable {
    assert(numVariables < maxNumberOfVariables, "Too many variables")
    numVariables += 1
    return Variable(number: numVariables - 1)
}

public func adopt(_ variable: Variable) -> Variable {
    if !varMaps.last!.keys.contains(variable) {
    // if top element in varMaps does not contains the given variable as key
        varMaps[varMaps.count - 1][variable] = nextVariable()
        // allocate a new variable for that key
        // I *think* varMaps[varMaps.count-1] is identical to varMaps.last!
    }
    return varMaps.last![variable]!
    // return the value corresponding to given key
}

public func adopt(_ variables: [Variable]) -> [Variable] {
    return variables.map(adopt)
    // just call `adopt(: Variable)` for each element
}

/// To sum up, variable adoption is used to reallocate id of the variables
/// The advantage for this operation is to make id continuous

private func internalAppend(_ instruction: Instruction) {
    assert(!instruction.inouts.contains(where: { $0.number >= numVariables }))
    // all variables in `inouts` cannot have id >= numVariables

    program.append(instruction)
    // append instruction into program:Program

    // Update our analysis, TODO: read these analyzers
    scopeAnalyzer.analyze(program.lastInstruction)
    typeAnalyzer.analyze(program.lastInstruction)
    contextAnalyzer.analyze(program.lastInstruction)
    updateConstantPool(instruction.operation)
}

public func adopt(_ instruction: Instruction) {
    internalAppend(Instruction(operation: instruction.operation, 
               inouts: adopt(instruction.inouts)))
    // create a new Instruction, 
    // but reallocate all variable id using variable adoption
    // then append it into the program
}
```

## 0x02 Mutation

### Mutator

Protocol `Mutator` is the base class of all mutation classes. The key method to be implemented is `mutate`, as the comment suggests.

```swift
/// Mutates the given program.
///
/// - Parameters:
///   - program: The program to mutate.
///   - fuzzer: The fuzzer context for the mutation.
/// - Returns: The mutated program or nil if the given program could not be mutated.
func mutate(_ program: Program, for fuzzer: Fuzzer) -> Program?
```

### BaseInstructionMutator

This class is inherited from `Mutator`, but it is still an abstract class. The `mutate` method has been overwritten, it uses `beginMutation`, `canMutate` and `mutate(:Instruction, :ProgramBuilder)` functions which are going to be implemented subsequent classes that inherit from `BaseInstructionMutator` (template method pattern).

```swift
public func mutate(_ program: Program, for fuzzer: Fuzzer) -> Program? {
    beginMutation(of: program)
    
    var candidates = [Int]()
    // `canditates` is now empty Int array
    for instr in program {
        if canMutate(instr) {
        // if the instrution can be mutated,
        // defined by specific implementation in child class
            candidates.append(instr.index)
        }
    }// append indexes of instructions that can be mutated 
    
    guard candidates.count > 0 else {
        return nil
    }// if `canditates` is still empty, return `nil`
    
    var toMutate = Set<Int>()
    for _ in 0..<Int.random(in: 1...maxSimultaneousMutations) {
    // maxSimultaneousMutations is a field of BaseInstructionMutator
    // randomly select a number in [1:maxSimultaneousMutations]
    // as number of iteration
        toMutate.insert(chooseUniform(from: candidates))
        // randomly select an index in `candidates`
        // and insert into `toMutate`
    }
    // note that since `toMutate` is a Set, 
    // the result size does not have to be number of iteration 
    
    let b = fuzzer.makeBuilder()
    // create a new ProgramBuilder using given `fuzzer`
    b.adopting(from: program) { // callback block
        for instr in program {
        // iterate over instructions in program
            if toMutate.contains(instr.index) {
                mutate(instr, b)
                // mutate instruction if it is in toMutate set
            	// to be defined in child classes
            } else {
                b.adopt(instr)
                // adopt the instruction
            }
        }
    }
    
    return b.finish()
}
```

### InsertionMutator

The `mutate` function defined is very simple, it adopts the original instruction, and then calls `generate` to randomly insert instruction(s).

```swift
override public func mutate(_ instr: Instruction, _ b: ProgramBuilder) {
    b.adopt(instr)
    b.generate(n: Int.random(in: 1...2))
}
```

**CodeGenerators**

Before covering function `generate`, we may need to understand `CodeGenerators` first.

`CodeGenerators.swift` is a file containing many code generator functions that can be used to generate a new instruction for `ProgramBuilder`. For example, this is the implementation of `IntegerLiteralGenerator`, which is used to randomly generate an `Instruction` of `LoadInteger`. 

```swift
@discardableResult
private func perform(_ operation: Operation, 
                     withInputs inputs: 
                     [Variable] = []) -> Instruction {
    var inouts = inputs
    for _ in 0..<operation.numOutputs {
        inouts.append(nextVariable())
    }
    for _ in 0..<operation.numInnerOutputs {
        inouts.append(nextVariable())
    }
    // allocate new variables as output variables
    let instruction = Instruction(operation: operation, inouts: inouts)
    internalAppend(instruction) // append newly created Instruction
    return instruction
}
@discardableResult
public func loadInt(_ value: Int) -> Variable {
    return perform(LoadInteger(value: value)).output
	// construct LoadInteger Operation from the given value
    // and create a new instruction using it
}
public func IntegerLiteralGenerator(_ b: ProgramBuilder) {
    b.loadInt(b.genInt())
    // randomly pick an integer according to context
    // and use that integer to create a new Instruction
}
```

**generate**

Then let's go back to function `generate`.

```swift
/// Executes a code generator.
///
/// - Parameter generators: The code generator to run at the current position.
/// - Returns: the number of instructions added by all generators.
@discardableResult
func run(_ generators: CodeGenerator...) -> Int {
    let previousProgramSize = program.size
    for generator in generators {
    // iterate over variadic arguments
        generator(self)
    } // call the generators
    return program.size - previousProgramSize
    // return number of new instructions
}

/// Generates random code at the current position.
@discardableResult
public func generate(n: Int = 1) -> Int {
    let previousProgramSize = program.size
    for _ in 0..<n {
        if scopeAnalyzer.visibleVariables.count == 0 {
        // if there is no visible variable, TODO: fully invistigate
            let generator = chooseUniform(from: primitiveGenerators)
            // randomly select a promitive generator
            run(generator)
            // use the generator to insert new instruction to program
            continue
        }
        
        var success = false
        repeat {
            let generator = fuzzer.codeGenerators.any()
            // codeGenerators: WeightedList<CodeGenerator>
            // randomly select a CodeGenerator
            success = run(generator) > 0
            // run until the program size increases 
        } while !success
    }
    return program.size - previousProgramSize
    // return number of new instructions
}
```

### OperationMutator

`OperationMutator` is used to mutate the content stored in `Operation`, in other word, the constants along with an operation. The structure of `mutate` method is shown below. 

```swift
override public func mutate(_ instr: Instruction, _ b: ProgramBuilder) {
    var newOp: Operation
    switch instr.operation 
    {
        // handle different kinds of operations
    }       
    b.adopt(Instruction(operation: newOp, inouts: instr.inouts))
    // adopt the modified operation, `newOp`
}
```

There are many cases, which are too long to put them here, and they are almost similar, so I will just choose some of them to discuss.

```swift
case is LoadInteger:
    newOp = LoadInteger(value: b.genInt())
    // create another LoadInteger 
    // but use another randomly generated value
case let op as CreateObject:
    var propertyNames = op.propertyNames
    assert(!propertyNames.isEmpty)
    // because instr.isParametric == true
    propertyNames[Int.random(in: 0..<propertyNames.count)] = b.genPropertyName()
    // randomly select a property name
    // and then replace it with another randomly generated one
    // TODO: investigate genPropertyName
    newOp = CreateObject(propertyNames: propertyNames)
case let op as CreateArrayWithSpread:
    var spreads = op.spreads
    if spreads.count > 0 {
        let idx = Int.random(in: 0..<spreads.count)
        spreads[idx] = !spreads[idx]
        // randomly select an element from spreads
        // and flip it
    }
    newOp = CreateArrayWithSpread(numInitialValues: spreads.count, 
                                  spreads: spreads)
case is LoadBuiltin:
    newOp = LoadBuiltin(builtinName: b.genBuiltinName())
    // randomly generate built-in name
case is LoadElement:
    newOp = LoadElement(index: b.genIndex())
    // genIndex is actually exactly same as genInt
case let op as CallMethod:
    newOp = CallMethod(methodName: b.genMethodName(), 
                       numArguments: op.numArguments)
    // randomly generate method name using genMethodName
case is BinaryOperation:
    newOp = BinaryOperation(chooseUniform(from: allBinaryOperators))
    // randomly select from all binary operators 
case is LoadFromScope:
    newOp = LoadFromScope(id: b.genPropertyName())
    // also uses genPropertyName
case is BeginWhile:
    newOp = BeginWhile(comparator: chooseUniform(from: allComparators))
    // randomly select comparators, 
    // this is also the case for EndDoWhile
case let op as BeginFor:
    if probability(0.5) {
        newOp = BeginFor(comparator: 
                         chooseUniform(from: allComparators), op: op.op)
        // mutate comparator for half propability
    } else {
        newOp = BeginFor(comparator: op.comparator, 
                         op: chooseUniform(from: allBinaryOperators))
        // mutate binary operator for another half
    }
// TODO: investigate `genXXX` functions in more detail
```

### InputMutator

Different from `OperationMutator`, `InputMutator` mutates the id of the input variables of the `Instruction`.

```swift
override public func mutate(_ instr: Instruction, _ b: ProgramBuilder) {
    var inouts = b.adopt(instr.inouts)
    // adopt the variables first

    let selectedInput = Int.random(in: 0..<instr.numInputs)
    // randomly select an input variable

    var newInput: Variable
    if instr.operation is Copy && selectedInput == 0 {
        newInput = b.randPhi()!
        // if instruction is Copy and input selected is 0,
        // the variable selected is the destination variable.
        // note that destination variable in Copy is 
        // input variable instead of output varaible. 
        // thus we must choose variables from Phi variables,
        // which are output variables of Phi operations
    } else if instr.isBlockEnd {
        newInput = b.randVarFromOuterScope()
        // choose a random variable from the outer scope
    } else {
        newInput = b.randVar()
        // choose a random variable
    }
    // TODO: investigate these 3 functions in more detail
    
    inouts[selectedInput] = newInput
    // replace the input element with newInput
            
    b.append(Instruction(operation: instr.operation, inouts: inouts))
    // append the instruction into the program
}
```

### SpliceMutator

`SpliceMutator` randomly chooses a existing slice of codes and adds it into `ProgramBuilder`.

```swift
override public func mutate(_ instr: Instruction, _ b: ProgramBuilder) {
    b.adopt(instr)
    
    // Step 1: select program to copy a slice from
    let program = b.fuzzer.corpus.randomElement(increaseAge: false)
    // now program : Program
    
    // Step 2 pick any instruction from the selected program
    var idx = 0
    var counter = 0
    repeat {
        counter += 1
        idx = Int.random(in: 0..<program.size)
        // Blacklist a few operations
    } while counter < 25 && 
    (program[idx].isJump || program[idx].isBlockEnd || 
     program[idx].isPrimitive || program[idx].isLiteral)
    // the picker trys not to pick these instructions
    // but could still pick if counter >= 25
    
    // Step 3: determine all necessary input instructions for the choosen instruction
    // We need special handling for blocks:
    //   If the choosen instruction is a block instruction then copy the whole block
    //   If we need an inner output of a block instruction then only copy the block instructions, not the content
    //   Otherwise copy the whole block including its content
    var needs = Set<Int>()
    var requiredInputs = VariableSet()
    // variableSet is a data structure that represents set of varaibles
    // using a bit array, read source code for more details
    
    func keep(_ instr: Instruction, includeBlockContent: Bool = false) {
        guard !needs.contains(instr.index) else { return }
        // only do something if it does not contain the given index
        if instr.isBlock {
        // if isBlockBegin || isBlockEnd
            let group = BlockGroup(around: instr, in: program)
            // given a Instruction, figure out the block it is in
            for instr in group.includingContent(includeBlockContent) {
            // iterate all instructions in group if true
            // iterate block instructions of group only if false
                requiredInputs.formUnion(instr.inputs)
                needs.insert(instr.index)
            }
        } else {
            requiredInputs.formUnion(instr.inputs)
            // instructions that procuce instr.inputs must be included
            needs.insert(instr.index)
            // current instruction needs to be sliced
        }
    }
    
    // Keep the selected instruction
    keep(program[idx], includeBlockContent: true)

    while idx > 0 {
        idx -= 1
        let current = program[idx]
        if !requiredInputs.isDisjoint(with: current.allOutputs) {
        // if the output of this instruction contains any required input
            let onlyNeedsInnerOutputs = requiredInputs.isDisjoint(with: current.outputs)
            // I *think* this always returns true for block instruction
            // because block instructions never produces output
            // e.i. numOutputs == 0 always
            keep(current, includeBlockContent: !onlyNeedsInnerOutputs)
        	// so only block instructions of group will be iterated inside here
            // if `current` is a block instruction
            // I am not sure why it is written in this way
        }
    }
    
    // Step 4: insert the slice into the currently mutated program
    b.adopting(from: program) {
        for instr in program {
            if needs.contains(instr.index) {
                b.adopt(instr)
            }
        }
        // add the slice selected into ProgramBuilder
    }
}
```

### CombineMutator

`CombineMutator` randomly selects a program and inserts the whole program into `ProgramBuilder`.  

```swift
override public func mutate(_ instr: Instruction, _ b: ProgramBuilder) {
    b.adopt(instr)
    let other = b.fuzzer.corpus.randomElement(increaseAge: false)
    // randomly select a program
    b.append(other)
    // and append it into ProgramBuilder
}

// ProgramBuilder.swift
public func append(_ program: Program) {
    adopting(from: program) {
        for instr in program {
            adopt(instr)
        }
        // adds all instructions in program
    }
}
```

### ConcatMutator

```swift
/// A mutator that concatenates two programs together.
public class ConcatMutator: Mutator {
// note that ConcatMutator is not BaseInstructionMutator anymore
public func mutate(_ program: Program, for fuzzer: Fuzzer) -> Program? {
    let prefix = fuzzer.corpus.randomElement(increaseAge: false)
    // randomly select a program
    
    let b = fuzzer.makeBuilder()
    b.append(prefix)
    b.append(program)
    // concat the program to be mutated 
    // at back of the randomly selected program
    
    return b.finish()
}
}
```

### GrowMutator

```swift
/// A mutator that inserts new instructions at the end of the program.
public class GrowMutator: Mutator {
public func mutate(_ program: Program, for fuzzer: Fuzzer) -> Program? {
    let b = fuzzer.makeBuilder()
    b.append(program)
    b.generate()
    // generate a new instruction
    // which is already covered before
    return b.finish()
}
}
```

### JITStressMutator

```swift
/// A mutator designed to call already JITed functions with different arguments or environment.
///
/// In a way, this is a workaround for the fact that we don't have coverage feedback from JIT code.
public class JITStressMutator: Mutator {
public init() {}
public func mutate(_ program: Program, for fuzzer: Fuzzer) -> Program? {
    let b = fuzzer.makeBuilder()
    b.append(program)
    
    // Possibly change the environment
    b.generate(n: Int.random(in: 1...2))
    // randomly generate few instrutions at back
    
    // Call an existing (and hopefully JIT compiled) function again
    if let f = b.randVar(ofGuaranteedType: .Function) {
    // randomly select a variable with function type
        let arguments = generateCallArguments(b, n: Int.random(in: 2...6))
        // randomly generate some call arguments
        b.callFunction(f, withArgs: arguments)
        // inserts a callFunction instruction at back
        return b.finish()
    } else {
        return nil
    }
}
}

public func generateCallArguments(_ b: ProgramBuilder, n: Int) -> [Variable] {
    var arguments = [Variable]()
    for _ in 0..<n {
        arguments.append(b.randVar())
    }
    return arguments
}

// ProgramBuilder
public func callFunction(_ function: Variable, withArgs arguments: [Variable])
                              -> Variable {
    // similar to LoadInt covered before
    // which creates a Instrution with operation CallFunction
    // and inserts it at the back of Program
    return perform(CallFunction(numArguments: arguments.count), 
        withInputs: [function] + arguments).output
}
```


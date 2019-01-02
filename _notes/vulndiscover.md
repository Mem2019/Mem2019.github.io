## data flow analysis

2 cve

## symbolic execution

### path explosion

add avoidance

## angr

document

deflat

## z3

## others

angrop patcherex driller rex

## pin

### source插桩

### static插桩

### dynamic插桩

**example**

`echo xxx | ../../pin -ifeellucky -t  ../tools/ManualExamples/obj-intel64/inscount0.so -o out.out -- ./a.out;cat out.out`

`../../../pin -ifeellucky -t obj-intel64/inscount0.so -o inscount0.log -- /bin/ls`

## afl

### opersource

change makefile compiler to AFL compiler

`./afl -i ./testcases -o ./output ./a.out @@`


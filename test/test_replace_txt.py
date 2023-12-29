import re

def replace_line(match, replacement, text):
    # 通过正则表达式找到匹配的行
    pattern = re.compile(match, re.MULTILINE)
    match_obj = pattern.search(text)

    if match_obj:
        # 获取匹配的行
        matched_line = match_obj.group(0)
        
        # 替换匹配的行
        new_text = text.replace(matched_line, replacement)

        return new_text
    else:
        print("No match found.")
        return text

# 示例文本
original_text = """This is line 1.
This is line 2, containing some keyword.
This is line 3.
"""

# 匹配关键字 "keyword" 所在的行，并替换为新的内容
new_text = replace_line(r".*keyword.*", "This is the replaced line.", original_text)

# 打印替换后的文本
print(new_text)

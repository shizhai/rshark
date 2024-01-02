import os

path1 = '/absolute/path'
path2 = 'relative/path'

result = os.path.join(path2, path1)
print(result)

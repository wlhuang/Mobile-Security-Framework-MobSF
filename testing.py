def find_position(data, search_item):
    position = None
    for i, item in enumerate(data):
        if item == search_item:
            position = i
            break
    return position

data = [
    {'identifier': 'Emulator_2', 'checksum': 'c5d872355e43322f1692288e2c4e6f00'},
    {'identifier': 'Emulator_3', 'checksum': 'c5d872355e43322f1692288e2c4e6f00'},
    {'identifier': 'Emulator_2', 'checksum': 'b3b44fcab9b2bcf1d9a9cfe42e8a8bd5'}
]

search_item = {'identifier': 'Emulator_2', 'checksum': 'c5d872355e43322f1692288e2c4e6f00'}

position = find_position(data, search_item)
print("Position:", position)

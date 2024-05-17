data1 = [{'identifier': 'Emulator_1', 'checksum': '536a67e11b59d27755241b90be29b44b'},{'identifier': 'Emulator_2', 'checksum': 'c5d872355e43322f1692288e2c4e6f00'}, {'identifier': 'Emulator_3', 'checksum': '536a67e11b59d27755241b90be29b44b'}]

data2 = [{'identifier': 'Emulator_3', 'checksum': '536a67e11b59d27755241b90be29b44b'}, {'identifier': 'Emulator_2', 'checksum': 'c5d872355e43322f1692288e2c4e6f00'}, {'identifier': 'Emulator_3', 'checksum': '536a67e11b59d27755241b90be29b44b'}]


def check_identifiers(data, currentlive):
    data_identifier = data[0]['identifier']
    print(data_identifier)
    for item in currentlive:
        if item['identifier'] == data_identifier:
            return item
    return None

print(check_identifiers(data2, data1))


# def move_to_last(data, target_dict):
#     for item in data:
#         if item == target_dict:
#             data.remove(item)
#             data.append(item)
#             break
#     return data

# if len(data1) != 0:
#     while check_identifiers(data2, data1):
#         thingtomove = check_identifiers(data2, data1)
#         print(data2.move_to_last(thingtomove))
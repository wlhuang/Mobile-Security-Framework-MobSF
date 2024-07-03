import os

# Initialize PATH variable
PATH = ""

# Loop until MOBSF_PATH is set in the environment
while 'MOBSF_PATH' not in os.environ:
    print("Environmental variable 'MOBSF_PATH' not found!")
    try:
        # Prompt the user to specify the path to MOBSF Root Folder
        PATH = str(input("Specify path to MOBSF Root Folder: "))
        if not os.path.isdir(PATH):
            raise ValueError("Please specify a valid file path!")
        
        # Append the path to the ~/.bashrc file
        with open(os.path.expanduser('~/.bashrc'), 'a') as f:
            f.write(f'\nexport MOBSF_PATH="{PATH}"\n')
        
        # Set the environment variable for the current session
        os.environ['MOBSF_PATH'] = PATH

        # Print the set path
        print("Path specified:", os.environ["MOBSF_PATH"])
        break
    except ValueError as ve:
        print(ve)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

PATH = os.environ['MOBSF_PATH']
# Check for the existence of certain files or directories
expected_files = ['EmulatorLauncher.py', 'manage.py']
expected_dirs = ['mobsf', 'scripts']
not_found_items = []
try:
    for item in expected_files + expected_dirs:
        if not os.path.exists(os.path.join(PATH, item)):
            not_found_items.append(item)
except ValueError as ve:
    print(ve)

try:
    if not_found_items:
        not_found_items_str = ', '.join(not_found_items)
        raise ValueError(f"\nThe path does not contain the expected items: \033[1;37m{not_found_items_str}\033[0m\n")
except ValueError as ve:
    print(ve, "\nPlease ensure that you have specified the correct MOBSF Root path!\n")

def box(msg, indent=1, width=None, title=None):
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'  # upper_border
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'  # title
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'  # underscore
    box += ''.join([f'║{space}{line:<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'  # lower_border
    print(box)

# Print the environment variable to confirm it's set in the current session
box(f"\033[1;37m{PATH}\033[0m", indent=1, width=len(PATH), title="Value of MOBSF_PATH found in ~/.bashrc")


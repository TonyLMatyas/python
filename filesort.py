#!/usr/bin/python


import os

def list_files(directory):
    """
    Lists all files within a specified directory.

    Args:
        directory (str): The path to the directory to list files from.

    Returns:
        list: A list of file names within the directory.
    """
    try:
        # Get a list of all files and directories in the specified directory
        files_and_dirs = os.listdir(directory)

        # Filter out directories and keep only files
        files = [f for f in files_and_dirs if os.path.isfile(os.path.join(directory, f))]

        return files

    except FileNotFoundError:
        print(f"Error: Directory '{directory}' not found.")
        return []
    except PermissionError:
        print(f"Error: Permission denied for directory '{directory}'.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def main():
    # Specify the directory to list files from
    directory = input("Enter the directory path: ")

    # List files in the directory
    files = list_files(directory)

    # Print the list of files
    if files:
        print(f"Files in '{directory}':")
        for file in files:
            print(file)
    else:
        print(f"No files found in '{directory}'.")

if __name__ == "__main__":
    main()


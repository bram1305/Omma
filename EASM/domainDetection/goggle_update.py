import git
import os
import toml
import sys
from pathlib import Path


config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)

# Add domain to goggle (discard domains)


def append_goggle(domain, file_path):
    add_data = f"$discard,site={domain}" + "\n"
    add_data_size = len(add_data.encode('utf-8'))
    current_size = os.stat(file_path).st_size
    potential_size = current_size + add_data_size
    if potential_size >= 2 * 1024 * 1024:
        print(f"The maximum goggle file size (2 MB) would be exceeded by this operation. The new size would be {potential_size / (1024 * 1024)} MB, the size of the added data is {add_data_size / (1024 * 1024)} MB. The current size is {current_size / (1024 * 1024)}. To add new instructions, remove other instructions from the file.")
        return
    with open(file_path, "r") as file:
        contents = file.read()
        line_count = contents.count("\n")
        instruction_count = line_count - 5
        if instruction_count > 100000:
            print(f"Instructions exceed maximum amount of 100000, please remove other before adding new instructions")
            return
    with open(file_path, "a") as file:
        file.write(add_data)
    return


# Push changes to git:


def git_push(
    repo_path, file_path, commit_message, remote_name="origin", local_name="master"
):
    try:
        # Open repository at specified path
        repo = git.Repo(repo_path)
        print(f"Opened repository at: {repo_path}")

        # Ensure file exists within the repository's working tree
        full_file_path = os.path.join(repo.working_tree_dir, file_path)
        if not os.path.exists(full_file_path):
            print(f"Error: File not found in the repository working tree: {file_path}")
            return

        # Stage file
        repo.index.add([file_path])
        print(f"Staged file: {file_path}")

        # Commit changes
        repo.index.commit(commit_message)
        print(f"Committed changes with message: '{commit_message}'")

        # Get remote and push
        origin = repo.remote(name=remote_name)
        print(f"Pushing to remote: {remote_name}")
        origin.push(refspec=f"{local_name}:{local_name}")
        print("Push successful.")

    except git.exc.GitCommandError as e:
        print(f"Git command error: {e}")
    except git.exc.InvalidGitRepositoryError:
        print(f"Error: The path '{repo_path}' does not contain a valid Git repository.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def update(domain):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    repo_dir = config["domaindetection"]["sesearch"]["goggle-dir"]
    goggle_file = config["domaindetection"]["sesearch"]["goggle-name"]
    commit_message = f"discarding {domain}"
    remote_name = config["domaindetection"]["sesearch"]["remote-name"]
    local_name = config["domaindetection"]["sesearch"]["local-name"]
    file_path = f"{repo_dir}\{goggle_file}"
    append_goggle(domain, file_path)
    git_push(
        repo_path=repo_dir,
        file_path=goggle_file,
        commit_message=commit_message,
        remote_name=remote_name,
        local_name=local_name,
    )


if __name__ == "__main__":
    args = sys.argv[:1]
    domain = sys.argv[1]
    update(domain)

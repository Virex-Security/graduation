import os

def nuclear_clean(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        skipping = False
        changed = False
        
        for line in lines:
            # If we see ANY marker, we treat it as a change
            if line.startswith('<<<<<<<'):
                skipping = False # Keep the next block (HEAD)
                changed = True
                continue
            if line.startswith('======='):
                skipping = True # Skip the incoming block
                changed = True
                continue
            if line.startswith('>>>>>>>'):
                skipping = False # End of skipping
                changed = True
                continue
            
            if not skipping:
                new_lines.append(line)
        
        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            return True
    except Exception as e:
        print(f"Error: {e}")
    return False

def main():
    root = "."
    count = 0
    for subdir, _, files in os.walk(root):
        if any(x in subdir for x in ['.git', '__pycache__', '.venv', '.gemini', 'node_modules']):
            continue
        for file in files:
            if file.endswith(('.py', '.yml', '.yaml', '.txt', '.html', '.css', '.js', '.bat', '.sh', '.md')):
                if nuclear_clean(os.path.join(subdir, file)):
                    print(f"Nuked markers in: {os.path.join(subdir, file)}")
                    count += 1
    print(f"Done. Nuked {count} files.")

if __name__ == "__main__":
    main()
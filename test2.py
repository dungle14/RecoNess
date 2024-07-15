import re

def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)

# Example usage
original_text = "\033[1m\033[34mhttp://kenh14.vn\033[0m [301 Moved Permanently] \033[1mCountry\033[0m[\033[0m\033[22mVIET NAM\033[0m][\033[1m\033[31mVN\033[0m], \033[1mIP\033[0m[\033[0m\033[22m123.30.151.82\033[0m], \033[1mRedirectLocation\033[0m[\033[0m\033[22mhttps://kenh14.vn/\033[0m]"
clean_text = remove_ansi_escape_sequences(original_text)
print(clean_text)
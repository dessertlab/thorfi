import json

def get_json_blocks(s):

    balance = 0
    parts = []
    part = ''

    for c in s:
        part += c
        # match open curly
        if c =='{':
            balance += 1
        # match closed
        elif c =='}':
            balance -= 1
        # if balance is 0 means that we found a block...save it
        elif balance == 0:
            parts.append(part[:-1].strip())
            part = ''

    # Capture last part
    if len(part):
        parts.append(part.strip())

    return parts


def parse_json_log_file(f):

    parsed_json_list = []
    json_blocks = get_json_blocks(f.read().strip())

    for block in json_blocks:

        parsed = json.loads(block)

        # we create a json file only with json block that have valid 'intervals' field
        if parsed['intervals']:
            parsed_json_list.append(block)

    if not parsed_json_list:
        parsed_json_list = ['{}']

    return ','.join(parsed_json_list)

import os, re
from colorama import Fore, Back, Style

rows, cols = os.popen('stty size', 'r').read().split()
rows = int(rows)
cols = int(cols)
def title(title, length=cols, filler='-', title_end='\n', color=Fore.YELLOW):
    # length = filler_length + title_length + filler_length
    title_length = len(title)
    if title_length < length:
        filler_length = (length - title_length) // 2
        filler_segment = color + filler * filler_length
        print(filler_segment + title + filler_segment, end=title_end)
        print(Style.RESET_ALL)
    elif title_length == length:
        print(color + title)
    else:
        print(color + title[:length - 3] + "...")

def table(data, column_widths = {}, column_labels = False, row_labels = False, row_justify="left"):
    if column_labels:
        column_count = len(data[1])
    else:
        column_count = len(data[0])
    if not column_widths:
        fixed_col_width = (int(cols) - column_count) // column_count
        column_widths = [fixed_col_width] * column_count
    if column_labels:
        table_header(data[0], column_count, column_widths, row_labels)
    else:
        table_line(column_widths)
    if column_labels:
        rows = data[1:]
    else:
        rows = data
    for row in rows:
        table_row(row,column_widths, row_justify)
    print(Style.RESET_ALL)


def table_header(labels, column_count, column_widths, row_labels = False, border_color = Fore.WHITE):
    if row_labels:
        print(' ' * (column_widths[0]+1), end='')
        print(border_color + '+' + '-' * (sum(column_widths) -
                        column_widths[0] + column_count - 2) + '+')
        print(' ' * (column_widths[0]+1), end='')
    else:
        table_line(column_widths)
    print(border_color + '|', end='')
    if row_labels:
        label_widths = column_widths[1:]
    else:
        label_widths = column_widths
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    for label, column_width in zip(labels, label_widths):
        label_length = len(ansi_escape.sub('', label))
        if label_length > column_width:
            label = label[:column_width-3] + '...'
        else:
            padding = ' ' * ((column_width - label_length)//2)
            label = padding + Fore.WHITE + label + padding + ' ' * \
                (column_width - label_length - 2 * len(padding))
        print(label + border_color + '|', end='')
    print('')
    table_line(column_widths)

def table_line(column_widths, border_color = Fore.WHITE):
    print(border_color + '+' + '-' * (sum(column_widths) + len(column_widths) - 1) + '+',end='')
    print(Style.RESET_ALL)

def table_row(data, column_widths, justify='left', border_color = Fore.WHITE, field_color = Fore.WHITE):
    print(border_color + "|", end='')
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    for field, column_width in zip(data, column_widths):
        field = str(field)
        field_length = len(ansi_escape.sub('', field))
        if field_length > column_width:
            field = field[:column_width-3] + '...'
        else:
            if justify == 'right':
                field = " " * (column_width - field_length + field)
            elif justify == 'center':
                padding = " " * ((column_width - field_length)//2)
                field = padding + field + padding + " " * \
                    (column_width - (field_length + 2*len(padding)))
            else: #Left and everything else
                field = field + " " * \
                    (column_width - field_length)
        print(field_color + field + border_color + '|', end='')
    print('')
    table_line(column_widths)

"""
Test Tables
table([['Column A','Column B','Column C'],['Row 1',1,2,3],['Row 2',4,5,6],['Row 3 has a very long label','This is a very long value.',[3,3,3],{3,3,3}]],[20,15,30,45],True,True)
table([['Column A','Column B','Column C'],['Row 1',1,2,3],['Row 2',4,5,6],['Row 3','a',[3,3,3],{3,3,3}]],[],True,True)
table_header(['a','b','c'],3,[30,15,15,15],True);table_row(['z','abcdefghijklmnopqrstuvwxyz',2,3],[30,15,15,15])
table_header(['a','b','c'],3,[30,15,15,15],True);table_row(['an especially long label for testing','abcdefghijklmnopqrstuvwxyz',2,[3,3,3]],[30,15,15,15],justify='center')
"""
def data_table(start_address, data, group_size = 4, border_color = Fore.WHITE):
    # +---------------------------------------------------------------------------------------------------+
    # |0x0000000000000000: 01234567 abcdef00 01234567 abcdef00 01234567 abcdef00 |abcdabcdabcdabcdabcdabcd|
    # |0x0000000000000001: 01234567 abcdef00 01234567 abcdef00 01234567 abcdef00 |abcdabcdabcdabcdabcdabcd|
    # |0x0000000000000002: 01234567 abcdef00 01234567 abcdef00 01234567 abcdef00 |abcdabcdabcdabcdabcdabcd|
    # +---------------------------------------------------------------------------------------------------+
    #  01234567 abcdef00 01234567 abcdef00 01234567 abcdef00abcdabcdabcdabcdabcdabcd
    cols_reserved = 23
    max_len = cols - cols_reserved
    group_count = max_len // (3 * group_size + 1)
    
    line_data_size = group_count * group_size
    raw_col_size = group_count * (2 * group_size + 1)
    line_size = group_count * (3 * group_size + 1) + cols_reserved
    
    column_widths = [16, raw_col_size, line_data_size]
    table_header(['Address', 'Raw Data (Hexidecimal)', 'Plain Text'],3,column_widths)
    
    previous_zeros = False
    zeros_start = 0

    for i in range(0, len(data), line_data_size):
        if all(v == 0 for v in data[i:i + line_data_size]):
            if not previous_zeros:
                zero_start = start_address + i
                previous_zeros = True
        else:
            if previous_zeros:
                zero_line = '----ZEROS----'
                padding = ' ' * \
                    (raw_col_size + line_data_size + 1 - len(zero_line))
                print(border_color + '|' + Fore.YELLOW + format(zero_start, '#016x') +
                      border_color + '|' + Fore.LIGHTRED_EX + zero_line + padding + border_color + '|')
            previous_zeros = False
            data_row(start_address + i,
                    data[i:i + line_data_size], column_widths, group_size)
    if previous_zeros:
        zero_line = '----ZEROS THROUGH ' + format(start_address + len(data) - 1, '#016x') + '----'
        padding = ' ' * \
            (raw_col_size + line_data_size + 1 - len(zero_line))
        print(border_color + '|' + Fore.YELLOW + format(zero_start, '#016x') +
              border_color + '|' + Fore.LIGHTRED_EX + zero_line + padding + border_color + '|')
    table_line(column_widths)


def data_row(start_address, data, column_widths, group_size=4, border_color=Fore.WHITE):
    # Prepare address line segment
    address = format(start_address, '#016x')
    
    # Prepare raw line segment
    raw_line = ''
    for i in range(0, len(data), group_size):
        raw_group = ''.join([format(f, '02x') for f in data[i:i + group_size]])
        raw_line += ' ' + raw_group
    if len(raw_line) < column_widths[1]:
        raw_line += ' ' * (column_widths[1] - len(raw_line))

    # Prepare plaintext line segment
    plaintext_line = ''.join(chr(i) if chr(i).isprintable() else '.' for i in data)
    if len(plaintext_line) < column_widths[2]:
        plaintext_line += ' ' * (column_widths[2] - len(plaintext_line))
    
    # Output results
    print(border_color + '|' + Fore.YELLOW + address +
          border_color + '|' + Fore.BLUE + raw_line + 
          border_color + '|' + Fore.LIGHTBLUE_EX + plaintext_line + 
          border_color + '|')


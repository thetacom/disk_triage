import os, re
from colorama import Fore, Back, Style

rows, cols = os.popen('stty size', 'r').read().split()

def title(title, length=100, filler='-', title_end='\n'):
    # length = filler_length + title_length + filler_length
    title_length = len(title)
    filler_length = int((length - title_length) / 2)
    filler_segment = Fore.YELLOW + filler * filler_length
    print(filler_segment +
          Fore.YELLOW + title + filler_segment, end=title_end)
    print(Style.RESET_ALL)

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


def table_header(labels, column_count, column_widths, row_labels):
    border_color = Fore.GREEN
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


def table_line(column_widths):
    border_color = Fore.GREEN
    print(border_color + '+' + '-' * (sum(column_widths) + len(column_widths) - 1) + '+',end='')
    print(Style.RESET_ALL)

def table_row(data, column_widths, justify='left'):
    border_color = Fore.GREEN
    field_color = Fore.WHITE
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

#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from ghidra.app.decompiler import DecompInterface

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app
import re

class Decompiler:
    '''decompile binary into pseudo c using Ghidra API.
    Usage:
        >>> decompiler = Decompiler()
        >>> pseudo_c = decompiler.decompile()
        >>> # then write to file
    '''

    def __init__(self, file, program=None, timeout=None):
        '''init Decompiler class.
        Args:
            program (ghidra.program.model.listing.Program): target program to decompile, 
                default is `currentProgram`.
            timeout (ghidra.util.task.TaskMonitor): timeout for DecompInterface::decompileFunction
        '''

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)

        self._timeout = timeout
        self.last_define_pattern = r'.*;\n\s*\n'
        self.canary_var_pattern = r'(\n|\s)*__stack_chk_fail'
        self.comment_pattern = r'/\*.*?\*/'
        self.file_path = file
    
    def decompile_func(self, func):
        '''decompile one function.
        Args:
            func (ghidra.program.model.listing.Function): function to be decompiled
        Returns:
            string: decompiled pseudo C code
        '''

        # Decompile
        dec_status = self._decompiler.decompileFunction(func, 0, self._timeout)
        # Check if it's successfully decompiled
        if dec_status and dec_status.decompileCompleted():
            # Get pseudo C code
            dec_ret = dec_status.getDecompiledFunction()
            if dec_ret:
                return dec_ret.getC()

    def get_last_define(self, func):
        match = re.search(self.last_define_pattern, func)
        if match:
            return match.group().split(' ')[3].split(';')[0]
        else:
            print('cant find last define var in function : ', func.split('{')[0].replace('\n', '').strip())
            self.file_path.write('cant find last define var in function : ' + func.split('{')[0].replace('\n', '').strip())
            return ''

    def get_canary_var(self, func):
        match = re.search(self.canary_var_pattern, func)
        if match:
            pos = func.rfind('if', 0, match.span()[0])
            substr = func[pos:match.span()[0]]
            # print("llk:  ", substr)
            return substr.split('\n')[0].split('= ')[-1].split(')')[0]
        else:
            print('cant find canary var in function : ', func.split('{')[0])
            self.file_path.write('cant find canary var in function : ' + func.split('{')[0])
            return ''
        

    def decompile(self):
        '''decompile all function recognized by Ghidra.
        Returns:
            string: decompiled all function as pseudo C
        '''

        # All decompiled result will be joined
        # pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = ghidra_app.currentProgram.getListing().getFunctions(True)
        for func in funcs:
            dec_func = self.decompile_func(func)
            if dec_func:
                # match the function __stack_chk_fail here
                if "__stack_chk_fail" in dec_func:
                    dec_func = re.sub(self.comment_pattern, '', dec_func)
                    if 'void __stack_chk_fail(void)' in dec_func.split('{')[0]:
                        # do not scan this function, it is always reported
                        continue
                    last_define = self.get_last_define(dec_func)
                    canary = self.get_canary_var(dec_func)
                    if last_define != '' and canary != '' and last_define == canary:
                        # match
                        pass
                    else:
                        print('Match fail in : ', dec_func.split('{')[0].replace('\n', '').strip())
                        print(ghidra_app.currentProgram.getName(), '\n')
                        self.file_path.write('Match fail in : \n' + '@' +ghidra_app.currentProgram.getName() + '\n')
                        # self.file_path.write('Match fail in : \n' + dec_func.split('{')[0].replace('\n', '').strip() + '@' +ghidra_app.currentProgram.getName() + '\n')
                        self.file_path.write('*' * 50 + '\n' + dec_func.strip() + '\n' + '*' * 30 + '\n')


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        print('[!] Wrong parameters!\n\
Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
-process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
-postScript|-preScript decompile.py <PATH_TO_OUTPUT_FILE>')
        return
    
    # If no output path given, 
    # <CURRENT_PROGRAM>_decompiled.c will be saved in current dir
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}_decompiled.c'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]

    # Do decompilation process
    fw = open(output, 'a')
    decompiler = Decompiler(fw)
    decompiler.decompile()
    fw.close()


# Starts execution here
if __name__ == '__main__':
    run()

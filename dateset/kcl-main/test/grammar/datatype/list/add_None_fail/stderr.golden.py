import os
import sys

import kclvm.kcl.error as kcl_error

cwd = os.path.dirname(os.path.realpath(__file__))
kcl_error.print_kcl_error_message(
    kcl_error.get_exception(
        err_type=kcl_error.ErrType.EvaluationError_TYPE,
        file_msgs=[
            kcl_error.ErrFileMsg(
                filename=cwd + "/main.k",
                line_no=4
            )
        ],
        arg_msg="can only concatenate list (not \"NoneType\") to list"
    )
    , file=sys.stdout
)


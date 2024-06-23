# Referred from airflow testsuite:
#
#   airflow/tests/decorators/test_python.py
#
# which has the following license header:
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import numpy as np
import pandas as pd

from airflow.decorators import task as task_decorator
from airflow.utils import timezone
from airflow.utils.state import State
from airflow.utils.types import DagRunType

from .test_base import DEFAULT_DATE
from .test_base import TestPythonBase


class TestAirflowPandasDag(TestPythonBase):
    def test_multiple_outputs(self):
        """Tests pushing multiple outputs as a dictionary"""

        x = pd.DataFrame({'x': np.arange(10), 'y': np.arange(10, 20)})
        y = np.random.rand(10, 20)

        @task_decorator(multiple_outputs=True)
        def return_dict(number: int):
            return {'number': x, '43': y, 'original_argument': number}

        test_number = 10
        with self.dag:
            dag_node = return_dict(test_number)

        dr = self.dag.create_dagrun(
            run_id=DagRunType.MANUAL,
            start_date=timezone.utcnow(),
            execution_date=DEFAULT_DATE,
            state=State.RUNNING,
        )

        dag_node.operator.run(  # pylint: disable=no-member
            start_date=DEFAULT_DATE, end_date=DEFAULT_DATE
        )

        ti = dr.get_task_instances()[0]

        r1 = ti.xcom_pull(key='number')
        pd.testing.assert_frame_equal(x, r1)
        r2 = ti.xcom_pull(key='43')
        np.testing.assert_array_almost_equal(y, r2)

        rs = ti.xcom_pull()
        assert rs.keys() == {'number', '43'}

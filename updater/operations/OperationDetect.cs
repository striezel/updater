/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace updater.operations
{
    internal class OperationDetect : IOperation
    {
        public int perform()
        {
            var listReg = detection.DetectorRegistry.detect();
            listReg.Sort();
            io.CSVWriter.toCSV(listReg, "installed_reg.csv");

            var listMSI = detection.DetectorMSI.detect();
            listMSI.Sort();
            io.CSVWriter.toCSV(listMSI, "installed_msi.csv");

            return 0;
        }
    } //class
} //namespace

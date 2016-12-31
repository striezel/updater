/*
    updater, command line interface
    Copyright (C) 2016  Dirk Stolle

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

using System;

namespace updater_cli
{
    class Program
    {
        static void Main(string[] args)
        {
            var listReg = detection.DetectorRegistry.detect();
            listReg.Sort();
            foreach (var item in listReg)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }
            io.CSVWriter.toCSV(listReg, "installed_reg.csv");
            Console.WriteLine("Hit Enter to continue...");
            Console.ReadLine();

            var listMSI = detection.DetectorMSI.detect();
            listMSI.Sort();
            foreach (var item in listMSI)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }
            io.CSVWriter.toCSV(listMSI, "installed_msi.csv");
            Console.WriteLine("Hit Enter to continue...");
            Console.ReadLine();

        } //Main
    } //class
} //namespace

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

using System;

namespace updater.operations
{
    /// <summary>
    /// displays version information
    /// </summary>
    public class Version : IOperation
    {
        string licInfo = "This program is free software: you can redistribute it and/or modify\r\n"
          + "it under the terms of the GNU General Public License as published by\r\n"
          + "the Free Software Foundation, either version 3 of the License, or\r\n"
          + "(at your option) any later version."
          + Environment.NewLine + Environment.NewLine
          + "This program is distributed in the hope that it will be useful,\r\n"
          +"but WITHOUT ANY WARRANTY; without even the implied warranty of\r\n"
          +"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the\r\n"
          +"GNU General Public License for more details."
          + Environment.NewLine + Environment.NewLine
          + "You should have received a copy of the GNU General Public License\r\n"
          + "along with this program.If not, see <http://www.gnu.org/licenses/>.";

        public int perform()
        {
            //Program version equals assembly version, so show that. 
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var ver = asm.GetName().Version;
            Console.WriteLine("updater, version " + utility.Version.get());
            Console.WriteLine();
            Console.WriteLine("Version control commit: " + GitInfo.getCommit());
            Console.WriteLine("Version control date:   " + GitInfo.getCommitDate());
            //show license information
            Console.Write(Environment.NewLine + licInfo);
            return 0;
        }
    } //class
} //namespace

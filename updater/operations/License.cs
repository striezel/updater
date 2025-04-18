﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2020, 2021, 2023, 2025  Dirk Stolle

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
    /// Displays license information.
    /// </summary>
    public class License : IOperation
    {
        readonly string gpl3Info = "This program is free software: you can redistribute it and/or modify\r\n"
          + "it under the terms of the GNU General Public License as published by\r\n"
          + "the Free Software Foundation, either version 3 of the License, or\r\n"
          + "(at your option) any later version."
          + Environment.NewLine + Environment.NewLine
          + "This program is distributed in the hope that it will be useful,\r\n"
          + "but WITHOUT ANY WARRANTY; without even the implied warranty of\r\n"
          + "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the\r\n"
          + "GNU General Public License for more details."
          + Environment.NewLine + Environment.NewLine
          + "You should have received a copy of the GNU General Public License\r\n"
          + "along with this program. If not, see <http://www.gnu.org/licenses/>.";

        public int perform()
        {
            Console.WriteLine("updater, a command-line tool to keep software up to date");
            Console.WriteLine("Copyright (C) 2017-2025  Dirk Stolle");
            Console.WriteLine();
            // show license information
            Console.Write(gpl3Info);
            return 0;
        }
    } // class
} // namespace

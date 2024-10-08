﻿/*
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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// unit test class for utility.Strings
    /// </summary>
    [TestClass]
    public class Strings_Tests
    {
        [TestMethod]
        public void Test_boolToYesNo()
        {
            Assert.AreEqual<string>("yes", Strings.boolToYesNo(true));
            Assert.AreEqual<string>("no", Strings.boolToYesNo(false));
        }


        [TestMethod]
        public void Test_removeTrailingBackslash()
        {
            Assert.AreEqual<string>("C:\\Program Files\\LibreOffice 5",
                Strings.removeTrailingBackslash("C:\\Program Files\\LibreOffice 5\\"));
            Assert.AreEqual<string>("C:\\Program Files\\LibreOffice 5",
                Strings.removeTrailingBackslash("C:\\Program Files\\LibreOffice 5"));

        }
    } //class
} //namespace

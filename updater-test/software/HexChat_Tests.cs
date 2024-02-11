/*
    This file is part of the updater command line interface.
    Copyright (C) 2023, 2024  Dirk Stolle

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
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for the HexChat class.
    /// </summary>
    [TestClass]
    public class HexChat_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new HexChat(false));
        }
    }
}

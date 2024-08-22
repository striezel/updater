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
using updater.detection;

namespace updater_test.detection
{
    /// <summary>
    /// unit tests for detection.DetectorRegistry
    /// </summary>
    [TestClass]
    public class DetectorRegistry_Tests
    {
        [TestMethod]
        public void Test_detect()
        {
            var detected = DetectorRegistry.detect();
            Assert.IsNotNull(detected);
            Assert.AreNotEqual(0, detected.Count);
            for (int i = 0; i < detected.Count; i++)
            {
                Assert.IsNotNull(detected[i]);
            } //for
        }
    }
}

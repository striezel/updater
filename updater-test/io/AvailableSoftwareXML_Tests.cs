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

using System.IO;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.data;
using updater.io;

namespace updater_test.io
{
    /// <summary>
    /// Zusammenfassungsbeschreibung für AvailableSoftwareXML_Tests
    /// </summary>
    [TestClass]
    public class AvailableSoftwareXML_Tests
    {
        [TestMethod]
        public void Test_toXML()
        {
            string tempName = BasicTest.getTempFileName();
            Assert.IsNotNull(tempName);

            var listOut = new List<AvailableSoftware>();
            listOut.Add(BasicTest.getAcme());

            try
            {
                //save file to XML
                Assert.IsTrue(AvailableSoftwareXML.write(tempName, listOut));
            }
            finally
            {
                if (File.Exists(tempName))
                    File.Delete(tempName);
            }
        }


        [TestMethod]
        public void Test_toXML_empty()
        {
            string tempName = BasicTest.getTempFileName();
            Assert.IsNotNull(tempName);

            var listOut = new List<AvailableSoftware>();

            try
            {
                //save file to XML
                Assert.IsTrue(AvailableSoftwareXML.write(tempName, listOut));
            }
            finally
            {
                if (File.Exists(tempName))
                    File.Delete(tempName);
            }
        }


        [TestMethod]
        public void Test_toXML_rountrip()
        {
            string tempName = BasicTest.getTempFileName();
            Assert.IsNotNull(tempName);

            var data = BasicTest.getAcme();

            var listOut = new List<AvailableSoftware>();
            listOut.Add(data);

            try
            {
                //save file to XML
                Assert.IsTrue(AvailableSoftwareXML.write(tempName, listOut));
                //load it from XML
                var listIn = new List<AvailableSoftware>();
                Assert.IsTrue(AvailableSoftwareXML.read(tempName, ref listIn));
                Assert.AreEqual(1, listIn.Count);
            }
            finally
            {
                if (File.Exists(tempName))
                    File.Delete(tempName);
            }
        }

    } //class
} //namespace

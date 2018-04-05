/*
    This file is part of the updater command line interface.
    Copyright (C) 2018  Dirk Stolle

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
using updater.versions;

namespace updater_test.versions
{
    /// <summary>
    /// unit tests for the QuartetAurora struct
    /// </summary>
    [TestClass]
    public class QuartetAurora_Tests
    {
        [TestMethod]
        public void Test_constructor()
        {
            // default constructor should set 0.0b0
            var qa = new QuartetAurora();
            Assert.AreEqual<uint>(0, qa.major);
            Assert.AreEqual<uint>(0, qa.minor);
            Assert.AreEqual<char>('b', qa.patch);
            Assert.AreEqual<uint>(0, qa.build);

            // constructor with parameter should set version numbers
            qa = new QuartetAurora("54.2a5");
            Assert.AreEqual<uint>(54, qa.major);
            Assert.AreEqual<uint>(2, qa.minor);
            Assert.AreEqual<char>('a', qa.patch);
            Assert.AreEqual<uint>(5, qa.build);
        }


        [TestMethod]
        public void Test_constructor_malformedString()
        { 
            // constructor with parameter should set only numeric parts
            var four = new QuartetAurora("12.3foo7");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<char>('b', four.patch);
            Assert.AreEqual<uint>(0, four.build);
        }


        [TestMethod]
        public void Test_constructor_short()
        {
            //constructor with parameter should set missing parts to zero
            var four = new QuartetAurora("12.1b");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<char>('b', four.patch);
            Assert.AreEqual<uint>(0, four.build);

            four = new QuartetAurora("12.1");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<char>('b', four.patch);
            Assert.AreEqual<uint>(0, four.build);

            four = new QuartetAurora("12");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<char>('b', four.patch);
            Assert.AreEqual<uint>(0, four.build);
        }


        [TestMethod]
        public void Test_Equals()
        {
            var quadOne = new QuartetAurora("12.3b56");
            var quadTwo = new QuartetAurora("12.3b56");
            // two instances should be equal
            Assert.IsTrue(quadOne.Equals(quadTwo));
            Assert.IsTrue(quadTwo.Equals(quadOne));
            // self equality
            Assert.IsTrue(quadOne.Equals(quadOne));
            Assert.IsTrue(quadTwo.Equals(quadTwo));
        }


        [TestMethod]
        public void Test_Equals_negative()
        {
            // two different numbers should not be equal
            var quadOne = new QuartetAurora("12.3b5");
            var quadTwo = new QuartetAurora("17.1a7");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new QuartetAurora("12.3b4");
            quadTwo = new QuartetAurora("15.3b4");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new QuartetAurora("12.3b4");
            quadTwo = new QuartetAurora("12.4b4");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new QuartetAurora("12.3a4");
            quadTwo = new QuartetAurora("12.3b4");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new QuartetAurora("12.3b5");
            quadTwo = new QuartetAurora("12.3b6");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));
        }


        [TestMethod]
        public void Test_CompareTo_Equal()
        {
            var quadOne = new QuartetAurora("12.3b4");
            var quadTwo = new QuartetAurora("12.3b4");

            Assert.AreEqual(0, quadOne.CompareTo(quadTwo));
            Assert.AreEqual(0, quadTwo.CompareTo(quadOne));
            // self comparison
            Assert.AreEqual(0, quadOne.CompareTo(quadOne));
            Assert.AreEqual(0, quadTwo.CompareTo(quadTwo));
        }


        [TestMethod]
        public void Test_CompareTo_Less()
        {
            var quadOne = new QuartetAurora("12.3b4");
            var quadTwo = new QuartetAurora("9.6b1");

            Assert.IsTrue(quadOne.CompareTo(quadTwo) > 0);
            Assert.IsTrue(quadTwo.CompareTo(quadOne) < 0);
        }


        [TestMethod]
        public void Test_CompareTo_Greater()
        {
            var quadOne = new QuartetAurora("9.6b1");
            var quadTwo = new QuartetAurora("12.3b4");

            Assert.IsTrue(quadOne.CompareTo(quadTwo) < 0);
            Assert.IsTrue(quadTwo.CompareTo(quadOne) > 0);
        }


        [TestMethod]
        public void Test_operatorLess()
        {
            var quadOne = new QuartetAurora("9.6b1");
            var quadTwo = new QuartetAurora("12.3b4");
            var quadThree = new QuartetAurora("12.3b4");

            Assert.IsTrue(quadOne < quadTwo);
            Assert.IsFalse(quadTwo < quadOne);
            Assert.IsFalse(quadTwo < quadThree);
            Assert.IsFalse(quadThree < quadTwo);
        }


        [TestMethod]
        public void Test_operatorGreater()
        {
            var quadOne = new QuartetAurora("9.6b1");
            var quadTwo = new QuartetAurora("12.3b4");
            var quadThree = new QuartetAurora("12.3b4");

            Assert.IsFalse(quadOne > quadTwo);
            Assert.IsTrue(quadTwo > quadOne);
            Assert.IsFalse(quadTwo > quadThree);
            Assert.IsFalse(quadThree > quadTwo);
        }
    } // class
} // namespace

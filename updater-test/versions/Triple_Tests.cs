/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2022  Dirk Stolle

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
    /// Contains tests for the Triple struct.
    /// </summary>
    [TestClass]
    public class Triple_Tests
    {

        [TestMethod]
        public void Test_constructor()
        {
            // default constructor should set 0.0.0
            var three = new Triple();
            Assert.AreEqual<uint>(0, three.major);
            Assert.AreEqual<uint>(0, three.minor);
            Assert.AreEqual<uint>(0, three.patch);

            // constructor with parameter should set version numbers
            three = new Triple("12.345.67");
            Assert.AreEqual<uint>(12, three.major);
            Assert.AreEqual<uint>(345, three.minor);
            Assert.AreEqual<uint>(67, three.patch);
        }


        [TestMethod]
        public void Test_constructor_nonNumeric()
        {
            // constructor with parameter should set only numeric parts
            var three = new Triple("12.3b.foo7");
            Assert.AreEqual<uint>(12, three.major);
            Assert.AreEqual<uint>(0, three.minor);
            Assert.AreEqual<uint>(0, three.patch);
        }


        [TestMethod]
        public void Test_constructor_short()
        {
            // constructor with parameter should set missing parts to zero
            var three = new Triple("12.3");
            Assert.AreEqual<uint>(12, three.major);
            Assert.AreEqual<uint>(3, three.minor);
            Assert.AreEqual<uint>(0, three.patch);

            three = new Triple("12");
            Assert.AreEqual<uint>(12, three.major);
            Assert.AreEqual<uint>(0, three.minor);
            Assert.AreEqual<uint>(0, three.patch);
        }


        [TestMethod]
        public void Test_Equals()
        {
            var tripOne = new Triple("12.3.4");
            var tripTwo = new Triple("12.3.4");
            // two instances should be equal
            Assert.IsTrue(tripOne.Equals(tripTwo));
            Assert.IsTrue(tripTwo.Equals(tripOne));
            // self equality
            Assert.IsTrue(tripOne.Equals(tripOne));
            Assert.IsTrue(tripTwo.Equals(tripTwo));
        }


        [TestMethod]
        public void Test_Equals_negative()
        {
            // two different numbers should not be equal
            var tripOne = new Triple("12.3.4");
            var tripTwo = new Triple("12.1.2");
            Assert.IsFalse(tripOne.Equals(tripTwo));
            Assert.IsFalse(tripTwo.Equals(tripOne));

            tripOne = new Triple("1.2.3");
            tripTwo = new Triple("2.4.6");
            Assert.IsFalse(tripOne.Equals(tripTwo));
            Assert.IsFalse(tripTwo.Equals(tripOne));

            tripOne = new Triple("1.2.3");
            tripTwo = new Triple("1.4.6");
            Assert.IsFalse(tripOne.Equals(tripTwo));
            Assert.IsFalse(tripTwo.Equals(tripOne));

            tripOne = new Triple("1.2.3");
            tripTwo = new Triple("1.2.6");
            Assert.IsFalse(tripOne.Equals(tripTwo));
            Assert.IsFalse(tripTwo.Equals(tripOne));
        }


        [TestMethod]
        public void Test_GetHashCode()
        {
            var trip = new Triple()
            {
                major = uint.MaxValue,
                minor = 0,
                patch = 0
            };
            int code = trip.GetHashCode();
            Assert.AreEqual(int.MaxValue, code);

            trip = new Triple()
            {
                major = 1,
                minor = 2,
                patch = 4
            };
            Assert.AreEqual(7, trip.GetHashCode());
        }


        [TestMethod]
        public void Test_CompareTo_Equal()
        {
            var tripOne = new Triple("12.3.4");
            var tripTwo = new Triple("12.3.4");

            Assert.AreEqual(0, tripOne.CompareTo(tripTwo));
            Assert.AreEqual(0, tripTwo.CompareTo(tripOne));
            // self comparison
            Assert.AreEqual(0, tripOne.CompareTo(tripOne));
            Assert.AreEqual(0, tripTwo.CompareTo(tripTwo));
        }


        [TestMethod]
        public void Test_CompareTo_Less()
        {
            var tripOne = new Triple("12.3.4");
            var tripTwo = new Triple("9.6.3");

            Assert.IsGreaterThan(0, tripOne.CompareTo(tripTwo));
            Assert.IsLessThan(0, tripTwo.CompareTo(tripOne));
        }


        [TestMethod]
        public void Test_CompareTo_Greater()
        {
            var tripOne = new Triple("9.6.3");
            var tripTwo = new Triple("12.3.4");

            Assert.IsLessThan(0, tripOne.CompareTo(tripTwo));
            Assert.IsGreaterThan(0, tripTwo.CompareTo(tripOne));
        }


        [TestMethod]
        public void Test_operatorLess()
        {
            var tripOne = new Triple("9.6.3");
            var tripTwo = new Triple("12.3.4");
            var tripThree = new Triple("12.3.4");

            Assert.IsTrue(tripOne < tripTwo);
            Assert.IsFalse(tripTwo < tripOne);
            Assert.IsFalse(tripTwo < tripThree);
            Assert.IsFalse(tripThree < tripTwo);
        }


        [TestMethod]
        public void Test_operatorGreater()
        {
            var tripOne = new Triple("9.6.3");
            var tripTwo = new Triple("12.3.4");
            var tripThree = new Triple("12.3.4");

            Assert.IsFalse(tripOne > tripTwo);
            Assert.IsTrue(tripTwo > tripOne);
            Assert.IsFalse(tripTwo > tripThree);
            Assert.IsFalse(tripThree > tripTwo);
        }
    } // class
} // namespace

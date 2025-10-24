/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2025  Dirk Stolle

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
    /// Contains tests for the ShrinkingQuartet struct.
    /// </summary>
    [TestClass]
    public class ShrinkingQuartet_Tests
    {
        [TestMethod]
        public void Test_constructor()
        {
            // default constructor should set 0.0.0.0
            var three = new ShrinkingQuartet();
            Assert.AreEqual<uint>(0, three.major);
            Assert.AreEqual<uint>(0, three.minor);
            Assert.AreEqual<uint>(0, three.patch);
            Assert.AreEqual<uint>(0, three.build);

            // constructor with parameter should set version numbers
            three = new ShrinkingQuartet("12.345.67.8");
            Assert.AreEqual<uint>(12, three.major);
            Assert.AreEqual<uint>(345, three.minor);
            Assert.AreEqual<uint>(67, three.patch);
            Assert.AreEqual<uint>(8, three.build);
        }


        [TestMethod]
        public void Test_constructor_nonNumeric()
        {
            // constructor with parameter should set only numeric parts
            var four = new ShrinkingQuartet("12.3b.foo7.8c");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<uint>(0, four.patch);
            Assert.AreEqual<uint>(0, four.build);
        }


        [TestMethod]
        public void Test_constructor_short()
        {
            // constructor with parameter should set missing parts to zero
            var four = new ShrinkingQuartet("12.3.4");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(3, four.minor);
            Assert.AreEqual<uint>(4, four.patch);
            Assert.AreEqual<uint>(0, four.build);

            four = new ShrinkingQuartet("12.3");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(3, four.minor);
            Assert.AreEqual<uint>(0, four.patch);
            Assert.AreEqual<uint>(0, four.build);

            four = new ShrinkingQuartet("12");
            Assert.AreEqual<uint>(12, four.major);
            Assert.AreEqual<uint>(0, four.minor);
            Assert.AreEqual<uint>(0, four.patch);
            Assert.AreEqual<uint>(0, four.build);
        }


        [TestMethod]
        public void Test_Equals()
        {
            var quadOne = new ShrinkingQuartet("12.3.4.56");
            var quadTwo = new ShrinkingQuartet("12.3.4.56");
            // two instances should be equal
            Assert.IsTrue(quadOne.Equals(quadTwo));
            Assert.IsTrue(quadTwo.Equals(quadOne));
            // self equality
            Assert.IsTrue(quadOne.Equals(quadOne));
            Assert.IsTrue(quadTwo.Equals(quadTwo));
        }

        [TestMethod]
        public void Test_Equals_object()
        {
            var quadOne = new ShrinkingQuartet("12.3.4.56");
            object obj = new ShrinkingQuartet("12.3.4.56");
            // two instances should be equal
            Assert.IsTrue(quadOne.Equals(obj));
            Assert.IsTrue(obj.Equals(quadOne));
        }


        [TestMethod]
        public void Test_Equals_Quartet()
        {
            var quadOne = new ShrinkingQuartet("12.3.4.56");
            var quadTwo = new Quartet("12.3.4.56");
            // two instances should be equal
            Assert.IsTrue(quadOne.Equals(quadTwo));
            Assert.IsTrue(quadTwo.Equals(quadOne));
        }


        [TestMethod]
        public void Test_Equals_negative()
        {
            // two different numbers should not be equal
            var quadOne = new ShrinkingQuartet("12.3.4.5");
            var quadTwo = new ShrinkingQuartet("12.1.2.7");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new ShrinkingQuartet("1.2.3.4");
            quadTwo = new ShrinkingQuartet("2.4.6.8");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new ShrinkingQuartet("1.2.3.4");
            quadTwo = new ShrinkingQuartet("1.4.6.8");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new ShrinkingQuartet("1.2.3.4");
            quadTwo = new ShrinkingQuartet("1.2.3.6");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));
        }


        [TestMethod]
        public void Test_Equals_negative_object()
        {
            // two different numbers should not be equal
            var quadOne = new ShrinkingQuartet("12.3.4.5");
            object quadTwo = new ShrinkingQuartet("12.1.2.7");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            object pseudo_quad = new string("12.3.4.5");
            Assert.IsFalse(quadOne.Equals(pseudo_quad));
            Assert.IsFalse(pseudo_quad.Equals(quadOne));
        }


        [TestMethod]
        public void Test_Equals_negative_Quartet()
        {
            // two different numbers should not be equal
            var quadOne = new ShrinkingQuartet("12.3.4.5");
            var quadTwo = new Quartet("12.1.2.7");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));

            quadOne = new ShrinkingQuartet("1.2.3.4");
            quadTwo = new Quartet("2.4.6.8");
            Assert.IsFalse(quadOne.Equals(quadTwo));
            Assert.IsFalse(quadTwo.Equals(quadOne));
        }


        [TestMethod]
        public void Test_GetHashCode()
        {
            var quad = new ShrinkingQuartet()
            {
                major = uint.MaxValue,
                minor = 0,
                patch = 0,
                build = 0
            };
            int code = quad.GetHashCode();
            Assert.AreEqual(int.MaxValue, code);

            quad = new ShrinkingQuartet()
            {
                major = 1,
                minor = 2,
                patch = 4,
                build = 8
            };
            Assert.AreEqual(15, quad.GetHashCode());
        }


        [TestMethod]
        public void Test_CompareTo_Equal()
        {
            var quadOne = new ShrinkingQuartet("12.3.4.56");
            var quadTwo = new ShrinkingQuartet("12.3.4.56");

            Assert.AreEqual(0, quadOne.CompareTo(quadTwo));
            Assert.AreEqual(0, quadTwo.CompareTo(quadOne));
            // self comparison
            Assert.AreEqual(0, quadOne.CompareTo(quadOne));
            Assert.AreEqual(0, quadTwo.CompareTo(quadTwo));
        }


        [TestMethod]
        public void Test_CompareTo_Less()
        {
            var quadOne = new ShrinkingQuartet("12.3.4.5");
            var quadTwo = new ShrinkingQuartet("9.6.3.1");

            Assert.IsGreaterThan(0, quadOne.CompareTo(quadTwo));
            Assert.IsLessThan(0, quadTwo.CompareTo(quadOne));
        }


        [TestMethod]
        public void Test_CompareTo_Greater()
        {
            var quadOne = new ShrinkingQuartet("9.6.3.1");
            var quadTwo = new ShrinkingQuartet("12.3.4.5");

            Assert.IsLessThan(0, quadOne.CompareTo(quadTwo));
            Assert.IsGreaterThan(0, quadTwo.CompareTo(quadOne));
        }


        [TestMethod]
        public void Test_operatorLess()
        {
            var quadOne = new ShrinkingQuartet("9.6.3.1");
            var quadTwo = new ShrinkingQuartet("12.3.4.5");
            var quadThree = new ShrinkingQuartet("12.3.4.5");

            Assert.IsTrue(quadOne < quadTwo);
            Assert.IsFalse(quadTwo < quadOne);
            Assert.IsFalse(quadTwo < quadThree);
            Assert.IsFalse(quadThree < quadTwo);
        }


        [TestMethod]
        public void Test_operatorGreater()
        {
            var quadOne = new ShrinkingQuartet("9.6.3.1");
            var quadTwo = new ShrinkingQuartet("12.3.4.5");
            var quadThree = new ShrinkingQuartet("12.3.4.5");

            Assert.IsFalse(quadOne > quadTwo);
            Assert.IsTrue(quadTwo > quadOne);
            Assert.IsFalse(quadTwo > quadThree);
            Assert.IsFalse(quadThree > quadTwo);
        }


        [TestMethod]
        public void Test_full()
        {
            var quadOne = new ShrinkingQuartet("9.6.3.1");
            var quadTwo = new ShrinkingQuartet("12.3.4.5");
            var quadThree = new ShrinkingQuartet("12.3.4.0");
            var quadFour = new ShrinkingQuartet("12.3.0.0");

            Assert.AreEqual("9.6.3.1", quadOne.full());
            Assert.AreEqual("12.3.4.5", quadTwo.full());
            Assert.AreEqual("12.3.4", quadThree.full());
            Assert.AreEqual("12.3.0", quadFour.full());
        }
    }
}

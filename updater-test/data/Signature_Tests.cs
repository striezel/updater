/*
    This file is part of the updater command line interface.
    Copyright (C) 2023  Dirk Stolle

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
using updater.data;
using System;

namespace updater_test.data
{
    /// <summary>
    /// Contains tests for the Signature struct.
    /// </summary>
    [TestClass]
    public class Signature_Tests
    {
        [TestMethod]
        public void ContainsData()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            Assert.IsTrue(sig.ContainsData());

            // Contains data also returns true for expired data.
            sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(-3.0));
            Assert.IsTrue(sig.ContainsData());
        }

        [TestMethod]
        public void ContainsData_MissingPublisher()
        {
            // Missing publisher does not count as valid data.
            var sig = new Signature("", DateTime.Now);
            Assert.IsFalse(sig.ContainsData());

            sig = new Signature("       ", DateTime.Now);
            Assert.IsFalse(sig.ContainsData());

            sig = new Signature(null, DateTime.Now);
            Assert.IsFalse(sig.ContainsData());
        }

        [TestMethod]
        public void ContainsData_MissingExpirationDate()
        {
            // Missing publisher does not count as valid data.
            var sig = new Signature("CN=foo, OU=bar", DateTime.MinValue);
            Assert.IsFalse(sig.ContainsData());
        }

        [TestMethod]
        public void ContainsData_None()
        {
            // The None read-only value does not count as valid data.
            Assert.IsFalse(Signature.None.ContainsData());
        }

        [TestMethod]
        public void HasExpired_positive()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(-2.0));
            Assert.IsTrue(sig.HasExpired());
        }

        [TestMethod]
        public void HasExpired_negative()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(2));
            Assert.IsFalse(sig.HasExpired());
        }

        [TestMethod]
        public void NeverExpires()
        {
            const string publisher = "CN=foo, OU=bar";
            var sig = Signature.NeverExpires(publisher);
            Assert.AreEqual(publisher, sig.publisher);
            Assert.IsFalse(sig.HasExpired());
        }
    } // class
} // namespace
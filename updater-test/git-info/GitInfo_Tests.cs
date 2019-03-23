/*
    This file is part of the test suite for the updater command line interface.
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
using System.Text.RegularExpressions;

namespace updater_test.git_info
{
    /// <summary>
    /// unit tests for GitInfo class
    /// </summary>
    [TestClass]
    public class GitInfo_Tests
    {
        [TestMethod]
        public void Test_getBranch()
        {
            string branch = updater.GitInfo.getBranch();
            Assert.IsFalse(string.IsNullOrWhiteSpace(branch));
            // Branch names may vary, so only mark test as inconclusive, if we
            // are on another development branch.
            if (branch != "master")
                Assert.Inconclusive("This is not the master branch!");
        }


        [TestMethod]
        public void Test_getCommit()
        {
            string hash = updater.GitInfo.getCommit();
            //Commit hash is a SHA-1 hash, i.e. 40 hex digits.
            Regex forty = new Regex("^[0-9a-f]{40}$");
            Assert.IsTrue(forty.IsMatch(hash));
        }


        [TestMethod]
        public void Test_getCommitDate()
        {
            string date = updater.GitInfo.getCommitDate();
            Regex expr = new Regex("^[0-9]{4}\\-[0-9]{2}\\-[0-9]{2} [012][0-9]:[0-9]{2}:[0-9]{2} [\\+\\-][0-9]{4}$");
            Assert.IsTrue(expr.IsMatch(date));
        }


        [TestMethod]
        public void Test_getDescription()
        {
            string desc = updater.GitInfo.getDescription();
            Regex seven = new Regex("^[0-9a-f]{7}$");
            Regex versionTag = new Regex("^v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}(\\.[0-9]+)?$");
            Regex versionTagAndCommit = new Regex("^v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}(\\.[0-9]+)?\\-[0-9]+\\-g[0-9a-f]{7}$");
            Assert.IsTrue(seven.IsMatch(desc) || versionTag.IsMatch(desc)
                || versionTagAndCommit.IsMatch(desc), "Description is \""
                + desc + "\" and does not match any of the regular expressions!");
        }


        [TestMethod]
        public void Test_getShortHash()
        {
            string shorty = updater.GitInfo.getShortHash();
            //Start of commit hash, i.e. seven hex digits.
            Regex seven = new Regex("^[0-9a-f]{7}$");
            Assert.IsTrue(seven.IsMatch(shorty));
        }
    } //class
} //namespace

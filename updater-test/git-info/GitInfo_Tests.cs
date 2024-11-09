/*
    This file is part of the test suite for the updater command line interface.
    Copyright (C) 2017, 2024  Dirk Stolle

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
    /// Contains tests for the GitInfo class.
    /// </summary>
    [TestClass]
    public class GitInfo_Tests
    {
        /// <summary>
        /// Checks whether getBranch() can get the branch name.
        /// </summary>
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


        /// <summary>
        /// Checks whether getCommit() returns a proper Git commit hash.
        /// </summary>
        [TestMethod]
        public void Test_getCommit()
        {
            string hash = updater.GitInfo.getCommit();
            // Commit hash is a SHA-1 hash, i.e. 40 hex digits.
            var forty = new Regex("^[0-9a-f]{40}$");
            Assert.IsTrue(forty.IsMatch(hash));
        }


        /// <summary>
        /// Checks whether a proper date is returned by getCommitDate().
        /// </summary>
        [TestMethod]
        public void Test_getCommitDate()
        {
            string date = updater.GitInfo.getCommitDate();
            var expr = new Regex("^[0-9]{4}\\-[0-9]{2}\\-[0-9]{2} [012][0-9]:[0-9]{2}:[0-9]{2} [\\+\\-][0-9]{4}$");
            Assert.IsTrue(expr.IsMatch(date));
        }


        /// <summary>
        /// Checks whether getDescription() returns a description with the
        /// expected format.
        /// </summary>
        [TestMethod]
        public void Test_getDescription()
        {
            string desc = updater.GitInfo.getDescription();
            var seven = new Regex("^[0-9a-f]{7}$");
            var versionTag = new Regex("^v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}(\\.[0-9]+)?(\\-rc[0-9]+)?$");
            var versionTagAndCommit = new Regex("^v[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}(\\.[0-9]+)?(\\-rc[0-9]+)?\\-[0-9]+\\-g[0-9a-f]{7}$");
            Assert.IsTrue(seven.IsMatch(desc) || versionTag.IsMatch(desc)
                || versionTagAndCommit.IsMatch(desc), "Description is \""
                + desc + "\" and does not match any of the regular expressions!");
        }


        /// <summary>
        /// Checks whether getShortHash() returns a shortened SHA-1 hash.
        /// </summary>
        [TestMethod]
        public void Test_getShortHash()
        {
            string shorty = updater.GitInfo.getShortHash();
            // Start of commit hash, i.e. seven hex digits.
            var seven = new Regex("^[0-9a-f]{7}$");
            Assert.IsTrue(seven.IsMatch(shorty));
        }
    } // class
} // namespace

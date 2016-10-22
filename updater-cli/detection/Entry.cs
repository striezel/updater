using System.Collections.Generic;

namespace updater_cli.detection
{
    /// <summary>
    /// struct that represents a detected software
    /// </summary>
    public struct Entry
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public Entry(string dispName = null, string dispVersion = null, string instPath = null)
        {
            displayName = dispName;
            displayVersion = dispVersion;
            installPath = instPath;
        }


        /// <summary>
        /// checks whether the entry contains some basic information
        /// </summary>
        /// <returns>Returns true, if at least the name of the software is set.</returns>
        public bool containsInformation()
        {
            return !string.IsNullOrWhiteSpace(displayName);
        }


        /// <summary>
        /// the displayed name of the software
        /// </summary>
        public string displayName;


        /// <summary>
        /// displayed version of the software
        /// </summary>
        public string displayVersion;


        /// <summary>
        /// path where the software is installed
        /// </summary>
        public string installPath;

        /*
        public int Compare(Entry other)
        {
            int c = string.Compare(this.displayName, other.displayName);
            if (c != 0)
                return c;
            return string.Compare(this.displayVersion, other.displayVersion);
        */
    } //struct
} //namespace

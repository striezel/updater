using System;
using System.Collections.Generic;

namespace updater_cli.io
{
    /// <summary>
    /// class to write an Entry list to a CSV file
    /// </summary>
    public class CSVWriter
    {
        /// <summary>
        /// default separator for CSV files
        /// </summary>
        public const char defaultSeparator = ';';


        /// <summary>
        /// writes a list of Entry structs to a file using CSV format
        /// </summary>
        /// <param name="entries">the list of entries</param>
        /// <param name="fileName">destination file name; existing file with the same name will be replaced</param>
        /// <param name="separator">separator character in CSV, defaults to ';'</param>
        /// <returns>Returns true, if the file could be written.
        /// Returns false, if an error occurred.</returns>
        public static bool toCSV(IEnumerable<detection.Entry> entries, string fileName, char separator = defaultSeparator)
        {
            if (string.IsNullOrWhiteSpace(fileName) || (null == entries))
                return false;
            if (char.IsControl(separator) || (separator == ' ')
                || (separator == '\n') || (separator == '\r'))
                return false;
            //generate CSV content
            string csv = "";
            foreach (var item in entries)
            {
                if (!string.IsNullOrWhiteSpace(item.displayName))
                    csv += item.displayName + separator;
                else
                    csv += separator;
                if (!string.IsNullOrWhiteSpace(item.displayVersion))
                    csv += item.displayVersion + separator;
                else
                    csv += separator;
                if (!string.IsNullOrWhiteSpace(item.installPath))
                    csv += item.installPath + separator;
                else
                    csv += separator;
                csv += Environment.NewLine;
            } //foreach

            try
            {
                var writer = System.IO.File.CreateText(fileName);
                writer.Write(csv);
                writer.Close();
                writer.Dispose();
                writer = null;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error whilre writing CSV to " + fileName + ": " + ex.Message);
                return false;
            }
        }

    } //class
} //namespace

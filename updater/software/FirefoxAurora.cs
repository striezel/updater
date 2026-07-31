/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "154.0b5";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dee4e497c2f032a790d75c6ec7979f9be06d5643b380e4ce0824f4a97f6ad68325be018f0baf0a429f308d15b12a2ab5174b27f6d700c8ea2475ee885208d800" },
                { "af", "bd50b7623c84699bc9618f21b6b43cb94b218381e506fc9d8b76429ac362d1222051b3eaaec32e934dbdedbb6cbe4c5e00213b539467e75ecc4f52749e61d963" },
                { "an", "8eb526f33382797990dae10cdefdd19521753f21c145912055be589b877dc13c9a05106021e58a5982dd4a0e98536c964767d85e6d71a7e3e4c82cd059fc3edb" },
                { "ar", "ae2e0dc0d89c2fe9f9df6d9cd9e2444de0dfee711ef7b69f1b176a9e069ef9137ba09c64430448d4901f1494f1302dab40326480611795b652629f94b88369cb" },
                { "ast", "aa9ce4547d0eaac042f3111ba29beb437042ee8bcf3be8d5ea202cfdf376b216e54ed5a8f36e189d699a41fe05d038dcef50bab7d180462a5b891e275a054370" },
                { "az", "e9a8d840e71e8d6074211c150f0c29da89eba03881a18bed9d28e6ce5c0dc06ca252dfaaf8c1883cf234abf8d35c82ee19037171895b1e388c461ab5c84f8483" },
                { "be", "431485489d402c035b4dba83cdbc355fe2b42176b281f289ebb9ea37db4de71f9188299d4b0f3cafff2244c63cdcd494b6608047e711fb7c2370144cb7ddcf34" },
                { "bg", "32a79fda4047b82e5358d0213c01ed887baab5e5a01eee08d2e260e56b917191a0144b165b94b03eda8b507e4e1831727750d7faff197ede617a061a84402e91" },
                { "bn", "23b5747fc7e007932f55dcf7dcb7e9eac415a5a27d368a7c8dfdc8c4021a37444daa0f4b33121271e3b7f95c10788a47ccfa4303c1aeb1226f82b2347e6db788" },
                { "br", "1e7872555c31bb332890f74728448172adbbe89f510bafb473a43d8cd2d8ae46dad83dc786f6734540f56dc75181b73efb0264f29ccdd4171018553799abd43e" },
                { "bs", "d36df8677d9b1866f496d90f2fa3b342797ad7deab3fcc7b8ffbf043d182b6e75a8be3a2103dc60568fdea58b993ae798864e044cd6368948306e0d3cf37bbb7" },
                { "ca", "f4cc5cfcfc92baf7bdab5854ae95bc37e3d6a7c7c354df45da6b258878c687a355ba1f0cdd5502664a26fc29f236295b6891d8aee5820197af8e14fb624065b0" },
                { "cak", "79b488eb3bd084212ede52e398f21abdb1a0fff769641637e0cc030e311406e62d60a656f3f91a31b370a5f7048f706d7f74119557ff87ca01a79968323e6eca" },
                { "cs", "66dbbaf0336b604cbf467fb3e08998e04bbb256a9167754316e3593aff59d5374e4e1cd88b8e78ddbd436b25beeccc0d7828644d300d981b1b42e3737d4944ef" },
                { "cy", "c323a02a4cf67b714e6a52e73b3a2acdce2778d173cfe8e04ef3bec4c8d0263f5a69f1bd0560f5d44e4aad4f498c7c3bdc1976e1c5d893b641328ac99d870727" },
                { "da", "b8165ad40bf0a66b84897eab0284990ba55af7b2ad41381adf782314ac80b9b18965c4ecbcdd987af527797e4b2b8e760ddfac10429ced947ff8dd1421aa2871" },
                { "de", "69a76929125c9e52a2a15fbd92683c7f1e36962622887648ddeda520903f9e1fcf4f58481de664282d674441128e387a921e74966a00bcc9cc0ea1f38a88ed16" },
                { "dsb", "6a4ef7c86aaf8e586ae70f96994362ea357ef9aceb1055fd6d8d3c8412002b89d2a470bfd945bcd1ada7de4762b17b155dd5839f251e1dde4ce705a94b3348aa" },
                { "el", "67812d47783f748713c2efc472136fd40ba5a4f8f159f908ec099913225e75f2d38ba3ad9773d4e31351604be6f6f2e7fb7fbfc102f36bbcfd93b0ccffc8e25c" },
                { "en-CA", "70b5a18ae00f7c84689f099303c5230205f498a85f77a3ef804379a3950729c6cb289af3e7d90c639729d1e5bade91bd82fa1243abc294a7330bff592cd47d6d" },
                { "en-GB", "7123c346a82a274bb75bc205765dabc739756254b579bfedb0271d6ac1bfe03f85d9f438251b0ddc32b9c0c7cc72b46a28c3b84ce07091f947a553b4a2d8887a" },
                { "en-US", "948743d8c3c0c4afadd2ec861c853c588623b6541d1c1aec929cad40880f70436e0166858b45580dc24a642ef2d2b8bd2cb10c6949cd45ea03933cf448522fc1" },
                { "eo", "1c4213d2a542256c794b4d0df3c8796981f04db76d8aefd4c2ad043e85d08fe74f3a904e6d70fd218cd6afe1ef19cfb394a9b1348e11eb32110135af3488994a" },
                { "es-AR", "7ab3206bc4153d99564e4a386a085fe2f8f0f4bdc9b234ca723b5b46132670fb8eb0623096909ea6fd3442ecffbf5aa4c1b4cbd067ca30cb673f9e2435b58e3f" },
                { "es-CL", "ed82eab60b2fca9944ca41683cb9a9a2c077e46fd86c29d3ef7f1e11bc7337d36bc36c755d9a651054a5826e1f672edbde65792e51a3bf8720a918c9dc3cc62b" },
                { "es-ES", "419f622de648c1c840d9f2c8f6ec1456c14402bf5f830e1ec2fd21bf4f3dfec6296b1b584fba52756efa1e275a6342bcbec80e1c0ce784a2dd4814791f7b8df8" },
                { "es-MX", "cc979c17c7d532dcfe57a4d096592d3139d9e16da8a651ce1b93e63184f7336e4a14bda4ef665dd9c554265e7e7ca5d7d9f929439d4024df853770111d31ac0c" },
                { "et", "3c653da3d63905dbfedb322ca1c978ea6d4b58f36fc45952a807e65a867026901e2e114417c846a44c45d01f037b34bf275c2a84ab8ba80af475afe471ed1807" },
                { "eu", "cccb23a808fea6c96d36595b25275b0c159ca3126d503e3a0f766d6f204bfb3db9cecb91fb564f21a01e386fa935045f8a4df9fa8302c26349b01986678e5225" },
                { "fa", "6544ca821d6d157ea588cc4824c6e173435f711ac390e72ce2f8e7c11c9123c72855e2c2c1b852f103095e257b479c57ceb57292d90683c7171e9ef024eebc9f" },
                { "ff", "d445166c1486b7824366a518ceff07d1efb611cf12ab623df4e070b6c9d8708c4fab605ceb009bb1c32223c846a5b0a632347302dd843d49be104def0ac5dc64" },
                { "fi", "28dfd93588e73729f0738afc677a14a6da9c327024da2c19d3b0515dd0b8677f005543e7a87c32c808b60a6a5822163a7f48a34cc7131ef0ec11c4d500976fbf" },
                { "fr", "538c8644b7ce7a8aac7c99671b77c39bfd8e443050dfd9c8e6f8b04def98e6048d19b2b9f210ff88a77513006391324fe95f903dcbcf878f02d5b2fa5c9bac3d" },
                { "fur", "e99e39a0d37e9feb4d5e6b8009e9860bd88f88b7de7f60658361bd47324caf28b83b5cd221ac8b540c31868ab77071078dec67e899acacac5473898ed251c17b" },
                { "fy-NL", "4f5a292d5f742038e7070c28d565d007811ae93d264d68503478b3a9e6d7ae983032f69b4b1516ee01b8dfef4b7b6a8634d06e62d72aa943297af96559ac017b" },
                { "ga-IE", "ac3ec171669fe13e02e90493a65a63a3d1f4b7ad6fb887755d1901dd71991377db72ed5241e9cda5b24cebce831dbe5b75b23fd0a443749adb8e68f9ddde9d0b" },
                { "gd", "cc1b9ba7dab72c6523aab6eecdb14763b1db0af22347be8a79c25c988ab1b512ebb4315f19282aac3ddbb8756a7b0a99c38b189a6e33c609c4f52cb7fed5895f" },
                { "gl", "8e2a6b9fb8a4f09cc1fcc2d694d7eeccec41dfc375371925e5cee8093a4a83c19902355eb5fb7ec7525f8ed3f1aba3a0fd48f6b1c665416b09fc2c9c33d3dc4f" },
                { "gn", "320450998a77744980f221ca74e88a6687d2f3dd0b4b6dc0959bc854cabf9e2e6509ecc7e6d25d9caf85e45739be81f6c9b3475c4c30af9032d5b4aea6d4f433" },
                { "gu-IN", "18c7e47bea25b95de19abc47d584c192bd4fc0515ed0385bc7947917e706bc06b79d361c3d5078ba8e0af11a07944c5045a717f536dcea48a3ce1353d7f31d13" },
                { "he", "16102016e03e2fb8956abb5f35d116cc00296c3ebd23e3ae0a0bf9b242c9de85188ce485dca4d340ccedce8b652ca635c12dbbb0815201ea1f9f89a16e797c67" },
                { "hi-IN", "b968d305f6a5c2a266a4d9869d530890453cbff7be3d8a1c305db3f195eaa0f5681d6c114e6622440a39dad1cd1511622acf4aa12f26a1959495809c53a0d522" },
                { "hr", "d0afde61d0f67b4fd6ab37f80a92c273d4d1c18051e52dd5a50cbfe914ef4f2bb54bd18a8294860f201ceb7a0c7aad0f011bd0712b37d7422d798c21d076ab3e" },
                { "hsb", "5804316d21395d5f572a0da65993ce90800d7f0869ee7d93c80df3f535039f92d5b524c006c6303fb47aa84395fd1d784d7c8c924d15a6ecc75332ee31699946" },
                { "hu", "ce7f9308dd4bd9bde8c1de404d3413e9be7ca4da7cc1b96104c3b6457647c5ed3f464ce1212c1b6198b230236afa0df9e012a937a096d167667fd83bd39c409a" },
                { "hy-AM", "8d4a398535121478ed6679bd88296409169c7871805e6a0c245a56ca7f041971bd5d8ade10b15ee1fa912be83d354cb434a14cff23beb36eb0a431d7d1423c5f" },
                { "ia", "89be2b70c839a494bfa8bec2a4358a28e1ed8851233e66c0b426beb0268320da840fcf482758108c64e886cee5e3daa5ac5396ac0ce3c14511418f1da6d6a343" },
                { "id", "052ccd44505e808397104e742b7e47d9580522321b8efbdf5e97ada6bef65e5d2b9fbeb8678eebd96618e42575092b2da8c7de1382444bce62d40ba37927a475" },
                { "is", "bc3328461a0a9ad13acf1847df2a7ab130e7fd3ce8634f5835e76a16759e6a1d604750698c57a2c71d752b2d92d34dab3a76ddf5a8a96604e08b218366c636e9" },
                { "it", "b1465579f99689fabf341c7b21fd4f907ee2264170bf10cffa4fef21fea4a7462adffe5d8551f7fed6d1ff30deb5c946ef837798b608cc5bd36b22e65dd5a055" },
                { "ja", "92cbd48cd1081887067473e8cca5555c490206f106e767b5898678146e7a9e3071aafaef18a2a6b017438669c3ea4b7d335e58b01ac8a337ace7f7c3e9417730" },
                { "ka", "09c1613c13f47481d3200ae4dca37c7033475e751e8ae1e337a873542c5b44d2846d764c992a55b77d3d27be89b61f1354120570d9664f8c5570b5d78a613415" },
                { "kab", "1404937158076acc0585e52221f4a42f9ebe8706bb503dcc873d20eb6931fd1106df8edb5d3207430242ec8fbc06d3a6c00caa5b2d1404ccb18f13ae751f41ac" },
                { "kk", "485898e841a4bc7d5885b4ff645e30eab74b4b8506e7a07ea8a9b00827a97546dffc63e808c56cf9df9f59512d714fe9b48be9e00622fff7a62580d6bc12be86" },
                { "km", "45f16efd0a8455df0ee86ac1f4f73d452f44701950cf2b0e09fdf3cbb5cbe901df44f6c01c29ba8965fb463309d529be1a0ed4d8f696bf270d22d02623ead8b7" },
                { "kn", "4dd0560ba5db03c24c4b8ef9f9d1e3fe78798831f33c0b28821168adf75a63808a7e38701044df5aa74a5fb04c3486ddf65aca027b3b8a415a42f16a581e4eff" },
                { "ko", "07e185d09a5e323dd23d540b08a8371259341ce97178b385c132fc05c481dc906599a534545ccd84146efec3fa7c4cf875f52f24e17269b3698bb9e4b621164c" },
                { "lij", "a07feb4b03f82fde44529cd4d07f3603b422595078930eb6cfc5e5d014c210b3b340bba83cfc48361b54ba26c39c6dcfb1a5ebd66bca917681492461579819f5" },
                { "lt", "a5eca95c19153c5fcb718c65583f03c6da5ee3ca78dd44cbaa298d30d39a4575dd43f7826111be831ea071521ed1d31d5e32ed94ee2345a9ff2b89d09105f63c" },
                { "lv", "44b29b211087101160ea0d68211b58b25950edb3bf33ce7a3b78fa6e31106afe2a28f240b8dfc9f2557ea1fa0cb29d0c8b8db4df91c93b2e6edafd95488a1dcf" },
                { "mk", "ea0e05a7b05e2f93866188944fd29e2059f0b60af04f0b1f6072e2c3771cd2ea8f3af77aa99694134f619002b37666abfde4a9491f37dd8808535f6914322c2e" },
                { "mr", "0d967bee67d1a85bfe1a9e566b827db6372292f70ee822d64e835257b0ddecea984939d7770d2e16d239e39672fbe75c17d6d52a85812c82c0faab4c37182476" },
                { "ms", "564b707da04313e87288cfefdf9dbae5ed075e302b26ba20a31aa32e2fe6417dbbd3577a880fc15796fd38bc6cc7f4e5bd414c7bfbce1e740b09c3015bf67bea" },
                { "my", "f0c9b61289e53459f735992e87262bcce1e0181ba7af14a07f895b255d8720151e36a4114489801f4f4a87d7b472944c849fd38964679144c0a760b8295b90df" },
                { "nb-NO", "17945fd39bfebce1e1a2ffa2d441010411efd4fa1032b014362fc126c91ec3a248a703368001d861d521c0fb9e3ba70bf5f0387848be91dabb107a12c01f87e3" },
                { "ne-NP", "13873eb42f5c80e85ceb934e81762c8b889a37a4398f5f3da00b950a3fb437eb14b2580a153217b9c0bb0a18b5da8db4e55a83a16ff50cca6c110a1f41c12200" },
                { "nl", "e32c2b48546fe2fbbff38307547e3b805b1b828ccd39f04b5265e4e4d2dba4d9623850b82d12d01d65618327fe17853803fddd320f9f61b5b4420d56e90bc137" },
                { "nn-NO", "a7dcf24810bfceff3111839305781c2858256d209de0eed0b6bc9ab51e561fde14783e1ba8a3dfc8201b83b882060d2a759d667b97f103bfb718aaccdb4949f8" },
                { "oc", "fed49c9a7c9ec780233bc95c4f7c36fa6de457e791f4731ba8f82de9eec3cd8aa882d6e5475bc5f987eb86a37753eb8797d02dc5723c947d98a45b45988001dd" },
                { "pa-IN", "41c7001bb13b54ec5744a9e2c5c3ecb93ae19b2ea812556535f6db54688da571e4f77a2a5990f8e8ba982106b810f940eea207966392e591b50f312b01beabbe" },
                { "pl", "3e37093167970132bd863ea299e9958fb674e141523f57c5303d7e9b2da2be5ad47911b9c79e4ac065f39425c4f3bcc8c99f4993bdb3cb94b85c5e300a2071a4" },
                { "pt-BR", "3c942a0d75ce33d2b30f45cd06a7b5b885788c1a4b3059cbd7fa52abe16753810d1ea12a229b1211ed2e1dc8221775bcc936dbfa17c1609959f1f795e7138462" },
                { "pt-PT", "a7a37b7b9bfdb6b5c723a4b44b797050f1d9343b0bcd23d1327e5d6148df332706ed217fd005fcdff97fb9bae58e5d0d47392292843c1bb596d6353f7d2efdde" },
                { "rm", "ffb5040142b37996b756374a2ce8ebe49cedcc0103a857bbaede5b5232801a7398dd027d06ffc435bbf97369e71483bd06a43d3f5ab297788d1a86a5a1928906" },
                { "ro", "1f3691d9482e163be952a356eb9d7d526466545030d8068db7af5a5e2ca7400674b92fb9462f97fcfc287053ee1de5e4a65f4e4174b0a507dbd084d3f4d168c3" },
                { "ru", "9e13a036509c6cb20c6a5b125798a441f6af21df812906e9b8d677733e6c22e81b7c29f0f1f81d56d39d3cc4bdd5593e8caa586dea70a73a40e86cd5629d549a" },
                { "sat", "e811b0eb9b19c22868d67db0dd73f9a69788a5859877b8dc32b6f66259bf0d676ab52649dcdf036ef8622d41c78596d02f6c8e0c1fe1fe05747f110eb085a1f7" },
                { "sc", "f01c5ba85550e31fe6c87ff2d042835348f5702286afaaa42fd0f6f8f363c9442c1336a656653955eac912a5db2e32c73de8454b2fd6110a964e1213c0e0f12e" },
                { "sco", "3dba3705d4885f55bae8d61a2b0d8792bf9e4e562d22f7fc76ca123d6d4479acdf86d514f1e64bc38e455fdbe9de0ce83707cdee3b5e025d340a0e98706fb048" },
                { "si", "798675ac39dcfb6fe7eb37b60d57991d11fce74f45020f07c89202a65e7f4e1cbda70048dd2460306ef2bc5063f9cf2841590920a1443fc2349b49ba8c8ecbc7" },
                { "sk", "461ab3852827d0b029553529cba1fd98a708c94d704ed4129e630922c23745c94e45d8fabf437a78e05da67fae50ce089a2ad127a746a232fdc5d8c8a6a744a7" },
                { "skr", "b6516e7c3f35a73826a0ec82b08e2b1453f4dda6207c83ba312c8647c771031a31f5ca3a970020e03f4fd271d7a9b3737c3fd9acd78f97b24a9ca7793fa89113" },
                { "sl", "e4fc2d690a66e9d53a1368dd469c74e2afbb2e2c1616993aad47e85c0c0dc0aad0ad4343176fd76de9f90f566e897de1d01ba183e59c2464aab20744fbf485dd" },
                { "son", "38d72ebfa98a71f290f923d4a5b672217e29db17fa69e53c38d1d92b19c38232ad86d9653f670c1e460933ae520a3e529e8e23b608ed6ff7e7feaac761c32179" },
                { "sq", "2b0e3e9ebc8201fed0f619b7fd26d3c4ff2e425116a744838e64c6b4dafd212ed33dbf7cc01e7ca47000b5a508ea8ad790082402fbcb1279abff76c201d56a34" },
                { "sr", "1f663e53dfb955772106adb34e952627bc96e090278e48d88f93bad83780b6adbf697de5b631d29a1dd3aa4090d9f1ddfd94e4ed4f6d50a050d88f72d73d9634" },
                { "sv-SE", "b589d793d5ea6c24a642c75734854b673f3ba45cfc11a1aa921a5f410b84142eaca95c8909959604bd7593cd17e77c803d8e1e360171daca429da04be0882a8f" },
                { "szl", "06f7fac3ac03447927b59704b8dd29643362bfe6c1b1e91c14d2c5d3650b3ddc137b2a81e4bc3c466543d72301db081a4f74f6e8dda4857775072d6d88d76a69" },
                { "ta", "7a775f417498f988bdf8077a4b8bff87f34fa6e41398c8a460632a59af6e3f854bd6f4bc922bd1afdfd1f0d3c81963556de61d114ef490b5f8b15c5016d979e7" },
                { "te", "260dc35a3578917f98ceddf6dc6e023cbe887a215abd716de94128a86e3aad1b6b77cef721ffa8409de71be17eff4ef60d3f5a5dbb69a3c9cd2efe8e2a35b314" },
                { "tg", "b2f30ff513a251e71ca4d45f38bcbdf9d238f6bfe7712544d39304a99dd34f1ea0c7bd044c0f79c0dbbae716774ccd5251f4ff216e1f5116fdd4864424532f9f" },
                { "th", "0bc59fac1af49ed42032e927aa473de7bdb8f0f62b00c28c7a348b3abbe6d53f4ebb081115b6a03bb558a37ec51cd54198fc78527b8bb012a4a00d46e9eef65a" },
                { "tl", "ff023614fa02f0d034e12fec8dd9f01b1fd0282821b01526bd4b897f26699b4ae84f5b3b47530c0b8d2edaa5fee84ba916305efc734c1692dbe83f2ae9307078" },
                { "tr", "15157ba83b0bf517733888a13c920b26100104d78bc96712c8935bd6326577fe432b956993e9e0ab3bbcbff2bef64d3770f5c78e37288419ded1dbcc4ed243da" },
                { "trs", "581a55532abc18e448b5b3f04016385558423179be11dc2d81e29b23697891a9f6bc0b141697410eef951005fa62a78ebbdbf3a59511371836bc7fdb59b830f0" },
                { "uk", "6fd7787961c489cdbbda369c6bc80244d00faff132daffbef9ffae7e2526835ac62a600fdf752f3a08b364148c319c9fbefb5626cf2340d4037c6e8498a2c429" },
                { "ur", "c246f869681d7936c0e10067db236967ad1f9d2b82608efc13fad31a8151fd203f64647da1365cb1e123a5c91028c1aba5953e6e4fdc6982c301496c09f4b8e2" },
                { "uz", "b236c274f231a0744a7d85130e0d17291e511647078233ed0af2ca574582855136858163644de121388bcd6a094d675b7849667d0160ec26b149f186aac6f95a" },
                { "vi", "96c781618a41ac5d1819373e32f4ad1e9ebe7cb4c3fe9d6684188f5d90b3310c6b3ebcfff9ca1a81942ddb15b7f4e6f2c10d776c1d179a21a46e9a478a41f4fd" },
                { "xh", "b55a83f3f06bc7664b818004c09c34396d9c915ca0a1368247e0cd66e77b1ba8ce7d79d32f306854a2382c455eb9bb5e31582ff30e1cc3e3b422e78fd5d6eb4c" },
                { "zh-CN", "014b7cfef4bb5cab34cc0113635071deb4e7b55f682d031d96bf83fa7918f437cd3269d6153912b9dcf9cdcd14c6b1fdc92461bd9d6743720aca56c0980612da" },
                { "zh-TW", "d9dc5d2ae66144aafd931deb881f00ecc01fcaec1138c9a26eeeee7e5834abac99899e2ed49502fd6b77042e06ac0c5601126bf0f6eb36fad7c1f187826da192" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4e6fe1b08d8f0a041646086e75764d9158892ec1d3076fa9db92881f0d9404ea6ffaa3fab6fa71a413e3700eecaac1e2fe7c359506d3ccc06e208a81e4b3a843" },
                { "af", "ee4c2a98d1e5965efd8de36565d83d3dccaaf4b48dc5c4aede043bd9bba21bc3b0854d49e31e61e13e50755620b8e43725b6e2998ade30b0a0ec83ef1a0f452c" },
                { "an", "98fae914aaf9b37a0ffa46cfd53c9673ccd34fc86951b060e90603b17f25ca89b9fbe801bb000783fd8a2bae171b7ebb645ad109a884236eeb5fb035871bc5c0" },
                { "ar", "8b0ab814532e0030a06d411ff39a51a3182b1afce85a5f74b4aba31b83b7b1af0d568bde59aae12c38ed5b0e87d63406212b27c192bf54fd6c9c4b2b5d4c9539" },
                { "ast", "d7a330af2af0821f8c1bb20867b0c4612f5eefb20e0bdc05973f0b6d045569a8f43e2be9abe6b497c13edc71dfbb35dea1438a721e804e748b99376f18bdc2bd" },
                { "az", "23059011bb0dcc39b0ada67c602c863b67942662803b89b6917abe430098ae59e27e11b0061126aa7a96329ed13e15fd8b47b7243e6da46e283fc4771543207e" },
                { "be", "6c60bf64986feeb2b6812aa09ac18e33f6368567181499eff26493db6b81e12b9efd8a47884e60f47e0bc3bfec444ea042ca72c02bc484ef06e9b67512754f24" },
                { "bg", "96559a3a58ca828698858140d6254e250d172d89b2edee9abf6a01cf51bff3247d580407edfcda42d309244b809d0aeb77f32a778d72f3465c6a8d0db697c64e" },
                { "bn", "8a5149c7e94043daa04adc9bd807df9211ca75e1a9407b542f12b50f5f557c431fff3acd945bd8f4966c2dcd5c7b8a2832f29cb0a892dd57fc55ddeeb50ae1f8" },
                { "br", "b50137a068556d8e8bde25e5c0737becba61192d321a7594b64460a1b11d90160b45dc05024553c0680995d7d31afd51de04c2dc2317abc1f6160784f477949f" },
                { "bs", "b38f12bf10688877cff9ca62335a5168fd65e1928c34bf0138899ea2c5276822d4afd9e2d569179a2229159861d338634f4009f6d10965265749b22ce1c037be" },
                { "ca", "4891a23b2da686df338a3a266456319307a64b9823c6100a633267f7afef5ec66eef1b63915cd89f2531127984d36ad460e01178be0e446295b19bd8cadc6ef2" },
                { "cak", "1ee7af0f1a0ced95f6de004b269064b3d46acc1ad562e73cdfa9c7edc917a35f19d088711cb609f2f5f9e9e69bb67ac168d21ae68f7d022eaf57fd5f7023faa4" },
                { "cs", "b30b4cc6411dc20e9e967cc86db0c69c49f935ed68e6724493691befa189a18fadad162e632b3e5dcb6b80959eb9d9860389f75ee070641cf4412aacc78954c5" },
                { "cy", "7399854e00e8a06e58f62e2289ea1ebd91afb057adf641464255cca054b106deb7af7777638cd275ef6d91d7b2f089ebd97d7d48ec95430aef40020b224e9856" },
                { "da", "c48e43e075d9116d0c39c6b312b51732147b3569d518723a2cca9248a537cb5aa04e0657bef537ca374a55cd7b52be9817a8b6735c9c6ef75514d6ab1caa36f0" },
                { "de", "5ccb1864ba8b684ec206c04920f09e54dbcd0e926e9d9ad77e7fcc84530019fc56f95298323cefce5a2ee8e6077521e698ba995d5fabed7eddeb4d816906c036" },
                { "dsb", "c8a9198c3ef90dbe1dcf6fc4637f4298bf009d8898476b0d1bcb4d47eb8a2d5779f7437b2be8512f5fbc551ba344296a3ece16192a506dcd910bd5123e9bd7b4" },
                { "el", "48342d8a0d75c9488d3de1109f18bba898b164edff1e128f1f16c1cb37255114a46c144bde21261e8750034f6826bdda2ec52f49396ea3717aa589240705b6d9" },
                { "en-CA", "d9aaed5cdffb8e0d81ef6dece9b01379804cfcba06cfc32d7f968f648dca546f2116ed140eb90945c17a8930240fb00650ccf9abac82108d19bb413f79504bcc" },
                { "en-GB", "68f455911b0a87b7ff20a0b9c735a6f25799cb4f1457e1819a1e42b60bc51768c59fecd1160bf8003cd88e36dffa6feac56a6f5c62d8ada27850947d664973ba" },
                { "en-US", "5280a893a20b7b70da36f6a3dc06da3575ea966b72a9099f3ba7d02c69297b05e90c71185ba3cbbb5a665bb153b951e23e28e33543054899e2721b9b59def284" },
                { "eo", "03a545d17da83a99c57b9fc6ae3493dea2c23aec87ad4161f754930bbb91ac2d5aba428f7e4cdd7ef447aae31e81b4ad9e6be2cb3094ba9335d05d7ab23b1990" },
                { "es-AR", "b8c1e7b5b7fe582061375bf38b4d2d7ab6eba906c603c727b80dffb28070eef584c787023d55d8af30649166a06fd100420185f863008c1bf032340df964faa6" },
                { "es-CL", "712d2802761b66042e3947edc2040544b90d43642af5cbf7e1cb561f9c5a438e1505a33d10544feaf19f43e19d4bfca67bb8e6a2f0f342d6cd349cb6ffdaf6f1" },
                { "es-ES", "b8a8d8b470f4376f16dc6ee10882a21488ba282498110c4884acc115984907c8c510a06d743029a958552b16acda8ffba84411f73d4dcf5ac1f3214d1198b551" },
                { "es-MX", "f20efc5ad253e18cfcf5174e8fe601653e83785b42ba04d9a3a422ff7c29dbb7f545d0080027e48eff4bd4f95d12d0155af8282cd83bb43f2a23546e51021f59" },
                { "et", "7f40bdf373e3ab480d84ae015b1b9a09936a8fc5f886f1c6b1b74e20e4d629b9789bfb7834422d3e2b6bf690ee91f5ddde2b84e9532a5ad517ff413cd85b3467" },
                { "eu", "46f6dca19daa2d62d95d22b6d1be70486552c96605d6d5aa43edaf081ece5771c6b9889ad72d7916b02fe19a42cdcbcdd8e8bfdae49dac8692e852ae14b9ddf8" },
                { "fa", "f1fddf7b1c8b1e314523e1ce3694acdafbcdda90d78766c3ce6a227627582028d80647b1e585a0e8e19b9d2fa8e92c4fd4bc412fbc9fc4d6d56887f0da8be898" },
                { "ff", "af33efa38d09bafc614ca33773a970c937e5d500dd6b4d5bc128eccafc5b4ff77d40b35f5d0e4b53c228fb681d31c331aafc1c756a1454c443c7efecbe5d397c" },
                { "fi", "f21599aa18e2f2a52e495b340255f506517e7c8012d29d627009f0eddb4a0e6595a9a7f480c420689645b5f6ac6a91c997237ae63e8c8b7d508be1b1ab9633de" },
                { "fr", "144b43dca80744b544f6519bd17c4a8ea7961fd718d5ea133a46e35ede8ede3e8747e13ff6baaf7bfb34bdf83b4fc5319234c16dd549f6706d061031f1c3ce9c" },
                { "fur", "0fad87e6074e0b72d4745af6f25365560b576945c50c79b141d538b531cad588a35ed7cd0e0fc995744d69a1b7f326311c9186ba271ef634d3bccf4065267323" },
                { "fy-NL", "66a69d554324c0082662ddd4e0b2d992fea272ca3f7bed555ce7ebc842bcb8356b1bd703234964f3d13b92b3b8bdbdd984317e813d2169524cc9ca51f276c27a" },
                { "ga-IE", "4770ed3984a96f562829827bfc31e522c40a6b43a642e40b7dc85d24454fecc565ad1dc08773b554c23f9e3622a48268701423fddf637f98205e41873d33494b" },
                { "gd", "1d98bba4f438240b6f3a65a0b4f7d5fe37575b35b6ee5668f0c16378f51dfecc58c02824bc0f607ba558c02160a62d2d05daa81d8c7bcae74578d835282911b0" },
                { "gl", "ab4baa709ca1e82028728da0b8c34379e558a62eeb46116287dba0ee4eaf4f5f337829ef725ebd57426a7296fa92e021ca9321cd3500b52fade6edf37694998d" },
                { "gn", "1963eb5027084ff1d26e4eb568bcf947ad35b56beb1c10c30fa69b5efbe7b13ae09b2cf3886db696f70670c33fef801ea34117b5815f9f85e04d33411dcf76ff" },
                { "gu-IN", "87f8286474d8ddee749d88bc0e479a45eae1f213ff58a9c4aefefb3fc66bf52ceb7bcec2622a5f8451dc0447749b8275e8822a0d85478cc19548dc6e7f4b10c8" },
                { "he", "128e020f644bb0175218a2291d050dc858f92793afdf051400adc9c02bd2f94400f1d9884bdef3180c6d1a1365e0f59bf1fbc2f419c636054d54b3f9c926d066" },
                { "hi-IN", "546e9208ba4d545004e69a2db3159ff0a50332429d29e3031ed5b280729b308162ea87ae972ef53b8c5dbe19e73fae8d9b217c988ceb4d6bb141995af70d0299" },
                { "hr", "a9bb73e468162e39091b398db0e5b38db978df1a88496c9306e03c0703593a6f92d4784fc721746e6ff75a04386bfe2b61b85126da9afda3487288b34b988beb" },
                { "hsb", "5760bd0759110bf0b3ba9eb539d7742658182e9b5aab7efec54ddfe077566533d9323422bdf12c102ee309a0260edb55c43c3061d6f2574211ef9f5f9b01f7a5" },
                { "hu", "5ffd32037c51905458a7e1eea0eb65430f7259b9551a312054fa391699c50afa69d7e03a4259858a767a657527361f6e720851e8465e41c476460576ed4c2ee1" },
                { "hy-AM", "5a877cfe18a31a8f511a94fa6539e13966a0cdf07ca265e4b9e336ac54737638085b8bae6c71db41ee3c3149e1f602cd241b147b859bf71ab6159342eee056f7" },
                { "ia", "86f2f11c57ce9547099148a565086feff6b5146d3e6a63a629163f6e5d2f99001c38389abb12c912a0193b77c489576719261bf7e7bb13b342e10acb67a6527b" },
                { "id", "f606d81f2f77b3060427d4a692fcbe52f5661aecf4abd57c01d55805f9a2bfb26f1d22879a890431779fd66c6782864db2f18494a29af1ccbfbbe7994e4cd3fb" },
                { "is", "02797ec67a2129fc41d046a453e1df8ad3ddcd00eb364c0c6063135d8bec3592a86c13a33cd945053b5616e07f7b0f813fb9522d49b7e73d778a315de65aa97e" },
                { "it", "47e104bd8e2ff2a0af990b3aae409b059f20283bd7403a2e65cf15bccc46f9267b5f82470d0ba3dc4a5ae08604d366a86e9f412bf319b8842c9c2660b3cba368" },
                { "ja", "e36579361d4071e7409eaf1709abb2e04c72a77503bdf0ce56c9b33244158406cf6eec1774abb27f73302e0236cc149aa10468360d6f269919a27f8ece1e3ea2" },
                { "ka", "186de4a764de9528ab8dc4e78ce8bd099552501bd5577aacc77d0d1c5a103da75bd014f57f390a1b166dfdcbf5b87abe14b9d6b41db271d65398584d97c02aa2" },
                { "kab", "a6a1637b683eb8041869811929edc68eebda806a417a31c98581839b0a95b3d77d2055bc0da78671d16fd74bf3ae53f0049aa0982b14159c50f27c3672246629" },
                { "kk", "b05ba063bbd411f371b38555617e797c9d4d294d66f70a02303e0cae56a0a134864581eb12d3154e5a365149b80acf8fd2c91479a773729a69ae4af8db445d7a" },
                { "km", "c19a1ef9dc2762ce7a8c796f69727ac16d472dae257b3687c210db1315ecb80b66df9eaaac255cfcef5fab06620109cc418bfe16d186fa092ef29f891c87cf16" },
                { "kn", "1b1f5ab6d678870fc622e9d5b18f749f1c1922b880e9da3da75c72855bc48495f5ceb54a90602a13a8e76f09171fbd6215596ee5f4b111900e688335ace01d6e" },
                { "ko", "3d4db61909e86a26efcefa9cee2455881f8676acb758ad931051c42dde35aa56b850e2afade3d5ab90d2ce0a065695d19a46bf8d06f88124294e1735f9c9ece2" },
                { "lij", "95b84d64317d7474901ff1a3ffe3f289dfd493462a8b22d51c490badc2fe0f4509c3976ae4cc64d9468ec1dcc48b35feffacfe79ef1a9ff3932eb48c285af616" },
                { "lt", "17d621ec7c08ea0f5c3386999b70388450db0d01c77a6cd15abe5041000c0b31b598383ec422fd60e13c2d2d78ce3431c4728330e8800fbed60765a87cfd7e03" },
                { "lv", "868853ea2064eb980df855507f22074454870b8c77689f6a9e65631eb2141ac9c459c4a03b226939cfc99310e0076874660ec017b03ad394876a1f1d5548abed" },
                { "mk", "1c2432f7d5359c983a6074bb1277b66e0724e8549c41621b762ed00cc38b0a44bd327796421f2657d04b2d92cc1e859bf17ff56fd83361256d9e0b472ba584a3" },
                { "mr", "3e0d350ed418ac77d6d3c21b97834c387b744225698ea1e268a27928606aca08f30f5b4092e81a77fbbd444d63d20d1b7c85126800eabd476362ac26e3fe00da" },
                { "ms", "9f179ccdcf6a7940fc03c9766be7e3f86a783dede8edcbf99f1dd662192d335fbf9407785119806c21ab0269c3a55c81dfcb1ebd6650a55aa8b1615be1b46514" },
                { "my", "bbe9455a91cdc3afb33212b38aaf5f2d988994e60b512d6c723f8bfbc84d25f74a014ab24a2f16918711f775f828b94e87863320c74eb7209fbb87420cf46c13" },
                { "nb-NO", "42f1881fbbfe661e1472116a7f97585230a0a5a1b65a915bb5f1fdff90dab301fe9327cfd4f16efcd73901522ecf4d7961ec55736e2e5039d06493a4ab65356c" },
                { "ne-NP", "edf70d1702a3d20398c1dba99971e2e667ea590844a36f7235234d8013aa839d39424911fbc32ac0ec03aad5a560c1e939eb10e2475b640f37cc8f3a1ae88e45" },
                { "nl", "3320d33fb160fc37c6fff965327c60845e009bf9084ab27cea6c7493555a0f93ca110140c7a96901b994ba2922d8a73c2e547aef65dfbaf6b417dc8841ea2be7" },
                { "nn-NO", "bce670e9e27b3d812c5eb2716f8acfa4c55fe3e83c445f126b5d2e8863978ebb0b04e4a2e1d79a0b07e701f012704814a9b34a45bde1ca2e5f30e6dd444147e1" },
                { "oc", "9955e80305ca54c284aefcf5436d98d29b11aa4d335ed660b2628529420c1e5fbedc57d05ca4c6acdf67b4e23985c24603d46a0e6e91a63a0062a98520b14bd9" },
                { "pa-IN", "4432730992562ef7bd08dafdf4d8221f2c57d3bd459b12089d5ef16a40a24583aa77386f6e4565087220bfad2a9cf0d28ac21dc01994780d18d0846adb2596a1" },
                { "pl", "851230376f9570883bcace478d291629cbfa1e9d0de3252c186bc051bd66a57ccca7fa02a6cd8cfa3699d0ac118eb2d69976efe4f3c978931bb82842414d688b" },
                { "pt-BR", "011e905c57fbb9911473e4d6d9066d94b19f353968022e1c321761e0d78eeb2392a16b168e8b8f1c24630042a92187817f6680c2d0a75406dcef9757dac747a0" },
                { "pt-PT", "6764d339a73f28d622fcb87b315a3a5473419e46457f47ee15aaba5fe47e67ff763755d0ccddf0b8867d6b6a8f9615d90e6e9291aa630f8d68f482c82ff377b3" },
                { "rm", "dcdf5136be693fb40fae97bc9f2656ae7d9eae04888d9602cbc47988536314783aac517ee4a44de58ad53f2e0f75c4fc1a44c8116a6b6fb3bf18848d05883c0a" },
                { "ro", "7953213f067ceef43a479172517c5215cbbe40c4f92ac371241562a30b434738f8d18807a7306b33e25b106d5ed4c6368965d18fae843922521c631bbdbac075" },
                { "ru", "4105456512e5581bd315c9a323e1b2aed65ef28159c636464898696d462108f51181ab80ec452e8b7b019b8a83ad5c780ebf568f4685c92dd58c3bb4c1517aee" },
                { "sat", "085e71de765f68b83512629eeff56a0b38e697ce7c97aadf6674deece439800e7d9e46afa16e2e1dc9ec62cafd87fda6acc1094227e6cb99087e297e54815e4e" },
                { "sc", "4433704d53ebff320cae81067536264ef07bfd617e3764a447e4584c3ba6201023215d61e771f17183b8c6e6a989f2f08fba5330e480407de22a05be1623b4fa" },
                { "sco", "f50c62c582ba866b272e4ceb0defd47d76d83e2b4b88a53ed31083f8669c5f20ddfac386f9447c075bed4a440dbe47eb2eb7dbf8120f941189688d04110b90af" },
                { "si", "c828d029152a9a6e0004141d9d9fae5e87a441a31301c9df66f433477fec7207d6adaa8c416cb83079ce35df98a86533428b50621f02e6e05d4bfda939b73566" },
                { "sk", "8075366bb55f8efebef887818974f83ea6148d60eac4f9ee684a285352f95f8fd71ad121401f681eebd8e5b9e750ed5ed294bd4d454f290c9ea60ad4dc102454" },
                { "skr", "65083bbfc034dd8bfd3e08ab6d0c24faf2f839e7ceef2704cf36aabb26cc5212d2a01856367fa8a313df6b63b2c34d81032b5d1ba9ddaa331087d9ede72e24b0" },
                { "sl", "db2db3e9b3b652ad9a3750ed599cbcd29d23e71a6536623519fe80b8cc0ee80738ea8583d2abade3c40bd9749758e5f7e10fa6b7785e20b030fac34c82bc6d0a" },
                { "son", "110be895d40bf7b60f561e6f871ae6082ef2d8eae26537e4233f0a1a30ea95e5703c76976af207566b4502cad017b1fc9ecba1b7bf1f3e493768fda9974b30dd" },
                { "sq", "b1016d90dcc0eaaa86eb1d9380919ad72a533c9d2c583cddc4f9a6eb300438a513f7fdbe1953674a5f8743058b891822525c3ff2b25f18132e36bf20cad0e83e" },
                { "sr", "752033e9d41dc9374293597bc8430527059c1a56f8a818a44c893bfa1de9bbddf357b8807c5949f449a921771d6dfc9f6f7c56923d37443555a7d43ffb51cbd3" },
                { "sv-SE", "e73269453c6847780aaea63ff6a9dfa391ff2b4d5e4db26b0adba80c3cc44871a585ef19a84ba8586c6b4e6fcdc307f234c41c2e9019fc72ed3cc86ce6c65b1f" },
                { "szl", "777929ba1031df1d6339199cfcfbbfeaf664f5504fa1ee5ec8a1a1a2d0f7abedb1eb7df60a7ae2775e7206b9cceb1d2562e3fdb85cfe2722c9228f50a182c718" },
                { "ta", "ded3c2ab17cc433648779915918d3541ca26f4b9a0f9f3ae5a29d1658e865fb872f273f645716a0775ba2e0a604c48b31be4a675c42e538f9c3984369a84e77a" },
                { "te", "af40d71cbf065747840cce2a7d5227f4dc9d829f11266b8e9e7f9780efaf163697e65c0d52c5290e28890b572343f15e67ecbae5e49327790df2ec990f5e0f7a" },
                { "tg", "157a58f1634aa5103e00132c5f5fac644e3fd1d510bd1af1a5e1d1547eb9b418a864d5cecac1616e8534567ad429bd3595890a77758eaffdf8622abccb23733b" },
                { "th", "6cde4173e99c4cf026c84eb78e10329c68d64ba73e2b11d8c58dcd6305a997a293fa3fa371c6a45d1fcd69744d6113f2b5feac9337ccab8cce8c8a9be1946772" },
                { "tl", "777d02a809c7ca6ff7d7cbec7af6796e55c0eed2a7ef5e7b108447f90376bdb64a4568a9b1cfd112d6ef90d25a9cad27dc939216ffa661f7570a26ba96acea1b" },
                { "tr", "c5d1f4cbbe37bcb8cd50564fd80f7efa4785bfef135844c8e5ae58541e2be095a1ab7643b4cab87b4a040498e913be82e05df56e09f8e7c52f32fc904eabb8f7" },
                { "trs", "b17799e57d7e42d8fc4ab866dcd152599fa742e907a472f53f355f9351e759a6c144a44025c3798c30d0da80ac34b223f4d2ff80205cada515a27b25c48b45ec" },
                { "uk", "4d3cf5f4298bad202cf9c36743c0273bc9ee26d568e62073fc7404fef090c377a5d5af5bf3f5cfe282a8dcd3d7947b1da6d36d55cec34f11b070476cbbb789e0" },
                { "ur", "0e8ec57f1be976a91a7d7e9633addf2b8645b13f7e7a72315361f061e17cddea12b894a8a8a726d3ebeaaa98133f10cc644b7aa22acbfb834c10fa6615f742cd" },
                { "uz", "728979aa29b7f28a1d98015449ef61d7d673c0e47d054292e7b63f46c0b4a4609e65b2d60e7bc69f1bd99503f0d9ac9a92c1ec3dc94d79d4612d7adb8186058a" },
                { "vi", "c6182607a85b89e79295b153bc24d5f0928d8b5569dba7c1dea3fadff9821deb45e09feb78ac783c10604563e7130022b5c3fd778d1455402545f5d4e649c6e9" },
                { "xh", "e2aea514f31aac88d8e3bd477f5fdddc8d0396c872fb1be650ab8e9c0e5bc39a4c0c7b71710dfe13e7b3f1bed12608fb582fe310e2805116ccee41cf3b97a97e" },
                { "zh-CN", "39196585648db7c831c1a3107370dcfa3fc893d4b024773e7b93ed5893007e7ddcf7e8a47e23316d1ef86f2d5080ee1751318916d01ab295cb9a4097f7392255" },
                { "zh-TW", "fc09bde8fad1bf8f70ea7f81540ebf1786e4ffa51cfea5ccc04054402eb3801af4a2f98925afdcf2e9570b5a988ede4fd68b49064f9e366df7ac49a28348813d" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace

/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.12.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f4eefe9170215f9fa74838755a063d8079fb803d4da098f86cbdeba7cdadf42c89deaa42981b994b0a9381a54f09445d0d3a1f21f581c8f128e317f09aa42760" },
                { "af", "b89f889c62e7801d1aa8fc1e60c49c735031586d2c0fa1aa550b33bfe89a624094b751dc968ced6eeb9dc31555da764ee84ce8d15f927906e44a9a4f9e3140b5" },
                { "an", "102382c30c780d006e7773ad682cd9628d7f5caafffb01fd2ac8f0244bf975e5f38f1d8c211094a9adc1399fbe8fc0925abeadae14d561fe13d301dad6e65891" },
                { "ar", "e580aeb39f2f0142db09f2d61969a01672b716c33841a33db0d1654fa946170c0b64f6f4970f5d8b7ceb05fa66fc2397446b06496be3aa995e3ae14f48242f73" },
                { "ast", "71c85e292351e541e888dd2973ee89b5a2fd43fdaadf6f8e41626161d3273eaa32feb56979c9f9950b19eeae0c1d2789cbe622af9018bd402e84d31b9aed820a" },
                { "az", "5f374d7c2e9a28c24d19d771c5b8e1ddeabf9f182371192cc2d2e4f4663c78ee3690398351cc84e1e7bf860e227e69addccaba04ae9957573d4a6cbf3ab40b77" },
                { "be", "bcbcbf1a2763bb2cc3d3a1d6011d168b6e3e0c927bde3b4e2f57116ac6d5bdb7974e65d267606781d3ac57b877ce13e27a1d69ebdacec11469fd4f438f9d5da9" },
                { "bg", "cb1c8b41d92a2bbfebfd02d8dceeb57a0ee9cfeb0a72c08a560442a46ba8568b4606ce7d6b0527ccb00375a38940ba0c4e9412fe15ce164f91114151d042d128" },
                { "bn", "17f3ed72c3304f6cbe5a465f60226417635eca6798dd434c9804313c02f95de046790d3e22db9059cea357768cb6e0515ae0a92c2dd4ae39123091e9cab6c60f" },
                { "br", "bc7552f281aecb3c9cacb12ceeccaac1c5ee4f60923f560f46b3bd0a0264f5e97522c2617c6a15978d43d12a94667da1fcd9bbb0833b01e72f9ac5c10dde5a0e" },
                { "bs", "40a56e051df8bb351095fad58f3ba39b59016cc68920302b1737a5e66699d03b1857448a14004538d5959e06e415726ec5841878a394c9d8c16abb8cc7d4d44d" },
                { "ca", "5cef327189b442600fa4152191598c6623672de272ba238e063553cb95a02cd4eb326fae0e92e979260e5982bd3a7f70c90833d67370564f3120640f4812a0a2" },
                { "cak", "f4715ef2d8c33250e282f2d5305efa12b21bbdbebee23dd59f75e0e4eb16a0136d18469948932468106fa5ea8cc68e8e055daf7044f385b1d50c423743ca47fe" },
                { "cs", "76c82d5fe4aceea81022f429f68e6265fb9c5395365485ddf2ac88e7319612955c874f0b342142d7478ccc4b0a519960fd8601a0cbc3d78c048b29bea97949e6" },
                { "cy", "93c327783eb87af68052ec670bc11bd4da98c4086b98ca2406d13516262c3b97e1c3c300bd3347ca2880e889989913b46deae163d4d5bb7f39a70a0fe9baefa0" },
                { "da", "5eaebb8e44571cabaad55b1f80b38ab0fc03f8bd2052cfe7615257e9edd23c194af97a0a0fbb9dd643f98c04e90dd2124dcf22b130a59af8f753bf0d76751812" },
                { "de", "8886aab975f7ffbfdfb1fc793b4011b7ab1045eadd79fd1df756c74dc7189f0fa3c1edd457fcdd5021f8dd52e1794199c6977a52426233857a58d83b81e1a54c" },
                { "dsb", "ad223d0b57131577ae65949e5d52a670aa32b779125ee18c2321fdf85eb3f8339f8b0c700985ee1c6c5bb1b19beaaccd215a24cc236a17ebf4c94bebbc8b076d" },
                { "el", "77c613d74d3b9cefb20aeb689330766b00f9723469a7dd365ce4deed062fa39fa9dabcfffe1a6e87f09bdb047ccb2e19814cde8a4dfbec535439d5ceabe8192b" },
                { "en-CA", "56ea144f4236971dd0ee74b43fb8812701873a3407976ecd92b7774314ada6e88462d0c16b26d1e7170756ca9e385c56472928e0d78108ce6981fa35c1e4d6e8" },
                { "en-GB", "5338fd821bbcfc70059273a33c2366aa2b674bdb93ef302ccdc9d72778763d1726d4be353d7a4506a13acc5ec59a2f9b6ad51a40aa9752dd28ff4499970cb107" },
                { "en-US", "f17dd20b8113446ef76f5b7be463256eca1c7d12b37d9c448f39322494211d1994cdaed13d33dee77ad844af32ef39511ad21d14900ce25ea23cd9a26086a88e" },
                { "eo", "b76f5fa92abfe813e0418fa7918c0a6657a3299261a8163961fd8cab8d9a22e09e597c5da63ca2f946c0e03263a1b60df68ec7d06c1c5eef0b17686a6d288d2d" },
                { "es-AR", "0448aebe3702e267640c8461051e3ef51ad0c2df144e17f0291008bd25c6fd05ab3a1867e5add50b0ad964c84db8e93d6857bff12d3fd30c68ccb3ea591f6319" },
                { "es-CL", "8d4b85b2b07fb2c275e2423acfd2323a541b6a9ada855f668aae851c465a5b13cd26cb614a381e57bbfd0d73ff1414bd06d9ef9b1fa5e34f51a2e524f03da6f2" },
                { "es-ES", "332147c501c35f9dfc9f40b49e60d36539a306008a1c846658be1ce3c6df21ebfc12f6c03a0d11f0642dc779033aa35350ad7d38acacb1267c08872197d04e3b" },
                { "es-MX", "3113882e61d042ba4cfbf0709798d936e126ae5a13b66075219af303818921298b1f81ba4374a5462a05b01e6afe2f9e2cf9d55383f6316f0e6381bcc7548a53" },
                { "et", "a7fe39f660c552670d20b1605af2b3bc97172e668543fa6aac42fa8f55692ef676b180fa581167a2582877ab3b3f943a9566f080e769c860db53ae4aa1f5c989" },
                { "eu", "3a377b938985b475d712d945d4abaa6035aa81345f253a87cf302c5847ce0bf910c4781294ee5649fec96b59ec504d2799b6ee4f146d87b081f95f25251963cc" },
                { "fa", "b9d3eb1e9ae7fa827699983f4b63414033691b996cc1421dfbd64bfeb47ba0aaacdbea024c8ae987be2f4c0fd5078725810e1c0051ca7f9efe13431902462baa" },
                { "ff", "154f9acbe5c4a9783663618b975b2358f38d1e697a95c12b647bc17692bd2ba8884e6bb034b4a0d8fac72ab0c941d86c75d9efc9988003b0b82fb3118c873f19" },
                { "fi", "52c0e92174dc051e7ff3ebaf62714059b0db81919b3dd4d908a1e1898d9efc2dfed29b9ef757a5babf99efe87a82da37fd45876673ecba8a9cf04be2bd600254" },
                { "fr", "f2870d0b77f38afb123aebb3c72a6bc91fddf5354ff71b665f5693635ff2711db0f5fe10963cf24fbf8916d6e0112b695e7730ed57e2246f77b8d636c03fac03" },
                { "fur", "eed50480ac27893d0172cd21e0546cf64b0a52da54550e5ec2de15896efda9daedf864ceffe58fc04554401ddaa93cd509d3a5d6d13a4e1bf7200963338223fd" },
                { "fy-NL", "0cfa56f96ea3cd40c33eea14e7adf47cb1063989b3451e6a8c2213a1cff09390829f428141c35ba1faf39736197f1412ebefeb35ef87adc387fb6331e9817b24" },
                { "ga-IE", "633b3146c9ea3f0b2726b079bc1699237b1e2716d92678aaaf23f7813fc1bda21185908e0232a5deaa5b14c08e9a7d027cf812cc7c9170a6ec6930b1c2e206bc" },
                { "gd", "fa76ce900e758007605e5fe94a0acbc4604f28e4ce9ab599d831baadf70b78d7171bbfc2e7372056b164fad61a52e31ce95d847ed4d50839ca0f63aebeeae3e4" },
                { "gl", "49bc724ddb26b3438d85f735b2c43a2a67e8d3352ab20e27b7ee309c751a397a768f6bcf3e60512405005e20bfd179447b2aa7c898c097a56e91f74130e334ac" },
                { "gn", "a6d0bc88b57491b28fffd45282062bfe8456df23e85721068c1bed72ebb560ff1f3742a887fa41544a79eb6fd5f658444052d818893e86e11a0e60ee9037b7dc" },
                { "gu-IN", "57df1fbd1e5f4d787ce97d9e6e2185425dab2d96148ccc3ed5bff60b27a6c247b821b778ff9acb020c0008e302254d6646024af6d3e13a70ba04cb9ed9af0921" },
                { "he", "2722ae8c252fba1baa0388629e80355bb2bdb419c7d4a5c0c3f5c18b91140a0de8d3c2965bc4d3e4194facd7f5d4b9fd2fc5bf557d1a0df071dea410b4def702" },
                { "hi-IN", "15fbef9747ce42af9b6f014f5eaa5a5058e218ac3f33a1174393b31bd7c567ee9adbae6597bf346c2aa62ca861405f67a6af471bb5291d214ad9af453a6465b3" },
                { "hr", "763c414ba4aca74a246e3b54b40559e559eacca901e66fb7e2872a114d0bf5e38d98fc25bd68fbe5f5b991d87ffc6b4f24e5bd6bd0a4fd409ef35dc5f9899edd" },
                { "hsb", "da310d1121459776129c5c2b811de45bf8748c2e5c0725085383bdb3ea649fb03a95a79144e4e81a1780a9588cabcfcdef72c0429f36a295168f64d852dbfc6e" },
                { "hu", "b12998aa203ee89436f5c303cf2c08393e00063873736453934ca0b1efcb2a21ae2e704358373e68d0571b328b5bb996ac070896b3054c1b4a96b4583713bf97" },
                { "hy-AM", "9c76dabbc7661b5e121cf47f87a836a8278ff3c945b5868065c7ff99d0e3fa54f89bfc8bc7d43da744b04d2d4797908e0c881d5b729844d9a3e655596666fc8c" },
                { "ia", "9d9edc56d1121c941c3e2583cd23d9215d8be6bd78ae7bba9c16da4fde3e386f0ed10d10e088da91b975fd02b7fbebc759ed2a7b86472b4869c36fd7835868c1" },
                { "id", "ecb8b629183c57e6e678aa0ff69fba335000da7e5bb9b52c31cb40ee222bec10c2a3cdb76dc5c40ab4ceacbdcb85172d319f6053bee0b07f2278692506d0fbb8" },
                { "is", "1f84e438c330ff62f25a4cb7f4f42c01954a0af742ce72c2649fbc5f9692dd355474349d08bdb6639cb3120817d934f889fc50ad516474c1ce289b5346e5ee8c" },
                { "it", "c60551f3c65aa7006fa3759c5e557b42173cb65285a1085e8279aecb342aab4b901728308e6ee99b84b5c8a8444ef34baecc8250d1f19b4f3b6dc9f983e160f7" },
                { "ja", "c4613253e03134ccf5288a613d27addfdc6ee2ae668e0a1232f293900da304fdd2f4ba1a4821d4aa6f8386f9ba966bf3bda3555375618728d1c861a43e20069f" },
                { "ka", "e3ad7089eebdd32979574e98c73c4f986e2d04e5fb76b2ed988083d672b10f2fa1af04d232ff870ffad379c2eb7f08102a9dadd0e6ca85fe4358b1691ce95e06" },
                { "kab", "ea116421edbea77f776235706c42f635cd5d13f5bfae078dfa68d3d3cd60a6378669c555e57facef252f3da8fc760d4a767d246b250f1c9d62db14fcb50b452b" },
                { "kk", "b879e3d29d9a7271a2b55bd397b93552978ac81c93dfff3d16ad08cde7f3ba1c3c1fbc5d284d831cd3e3a23808ee4d102b22aae12c9ae6da7ccabfa5e037027e" },
                { "km", "158019bbc3a0ecf5e2f39ec70c8341732cff5473956c2fcadb3973d3159282961444685f4100ef234f042dafb3459120c354ac62f41e41986f3945127db3fd8d" },
                { "kn", "b73e05e3351b9203977422018d7bda69fb05ef2715ef84ed71bf4fb85ecd1223974137a1c5997d7fb24eb4725bd944e8244b66043234ecec4aec91ff63e31aa9" },
                { "ko", "19b8067b7374c33398b21c4228c25279a447857f93dc6f2e84c354c71b62b85901544248cd0046226c515474db159c1233fce4a2d80f574c79b6e933852ac0e0" },
                { "lij", "dd3618e5766571757ec93a589b2726166f54135ce936d5d06d1db3d5fafaf3c5a718a180df85bbbc5c8d078ed7347c0e20077bd15d412cde072d1b347d2d5efc" },
                { "lt", "0e74a34870248ef2a7c3c3e4304a5aabd3df21d29cad3b4053568f8d647ae089b16ef04fe887c771ac0d1eae55f1c689e08582222d27ac5d0b77a2e391908dba" },
                { "lv", "6dabc46595a52d991dc6ad3874c142d04d91d30a276ff8ac7097dc397a20936fead24de3e5c451bb061ac447929e43cdd74475ebea93c97eb0ea47a802530628" },
                { "mk", "98cef45ce18d75e56a99e10966046def83ac71beffa07f48f6d043b8c0ca398dfb96fd24ed3757dd2f0867ac7c4f9a86f742ad1a56f89e93a84bce3b19f80e74" },
                { "mr", "6e7c712fceb96baecb0ed1066e29afc8fc6b279edb68a03f67911012b583e4e6b5e18c999ab0551adf60ecc2aef8e5432b30c732a660a05c976a34a375b094de" },
                { "ms", "323f4b2ac24af3d43947cf291a27197716969e626d978dd9cb9515ae54b7cf10cbc2fabe25d952e449e9869537f3abf0bb1251a4fde21c7639c7c04822899b0b" },
                { "my", "90e810dd558109d3fa072ef8228dc30d25a6be610ebd3a2ceff967a3d65bec90c222062feb35f4a955dbe22dc0ed39bd6fcfa44c6b168e1b7d3dbd03bfba263b" },
                { "nb-NO", "69f06ef0f56089b41fc271474ff15afe6b2d463829cbeef0ba6fc6f2725b373a8b66c25401d803d1efa53dbe41dcf5aeedaed38f2888f4f2834860949b3d2fbc" },
                { "ne-NP", "4c741a2e40841b5167278d37da801d0353f0ca3b745cd6b57ef25eb51827986d9236903db740967c4fc4b205a4226bfc94cd9a5f5ec5d86c5c5c3aa1583d7df9" },
                { "nl", "70c4c58a090a24b3f9bc7ffad08442a75b621859ac0f7b188aa88005ee80aa99746b19cacd42736539c9b18d828facbbc710805052db61a038af8c6176bb316a" },
                { "nn-NO", "db600daf6b5b2d0f19274a806ad31179b3bcc5d3a37ecf8c436ea8430a55a5385304ec797a19d739b4a7c3902675dc00128ff294df2e526f73a61a667ecd72c2" },
                { "oc", "85ab51898942eb6022500aeaffed1d291b08692fb02d7cfd9ac822fbeb09920fc4b2241acb17ceeaaa2e81a81f648d4d879b51a5c80aa3bb046b3f0132f9876f" },
                { "pa-IN", "6445577f49985ceb8af6a5b8f7a1b39015c9d333a5bf755e819c550ccc533aa833aaa103fdc6ad46e6b366f3ee22c3a02670f3b4bc7d34fef30f9e80db532e89" },
                { "pl", "f19d74397a647c2a0fd656a1241ac600988ab4098ab7ddb551f00242ae7283d4bdc20d75cedba7959e5e066216df38d2aa417556c1549f7fed681c8f68255220" },
                { "pt-BR", "dfa764e4750c0729545b75dddec8a5c4a8c24ae1a4d4f93b1c3d0389b0d7d0360f3db12e99104cea7dcdd37b5f0c3cf3245ccfd82f1113f009baeff0f7cc6c0d" },
                { "pt-PT", "fd519b10958c7bce57d1e1dcf609c10e9a8e859a481c9f28fdbf947b1c31b841c6caa0a3cb09185c27fbaae97e127a837f1fe9739a51216b53986063f89a59e2" },
                { "rm", "2ef843cf4ec0ef8ca0d71233c9d408a56f3b67189f69594f308ffdb328e9547c61af12df9a4c55b4b42e49b9908fc0b0253c9b36c8ebb54def16e518fb1054c8" },
                { "ro", "824b381e86886961073ee2dfe6997a3eeb1be892e940adfa733616f30892202d61d445d08f505afb3569f6a0687fa8543241ca6ce945437aeea10393375d2fe2" },
                { "ru", "f6a1dff1f472029984654bff812a31542e431ecf8b1093dba7715c59af846cb6f0b63fedd7901a5edf9a3503a7781400183ad16adfd272397a2e3f2a64da9da6" },
                { "sat", "336a15c0ae6fc4ed7dbdd455fe86dfa8293bfb8d7b57b3ba4f6240de69c7999b748d02495f29c8eec2641ba95818bf6de54b495d37f1237ab4a780c8c96f62b1" },
                { "sc", "469b4d9a31d31c3f9fb58e770acdd3b0fdcb1decfa74d2c2a6d5c7b3734e1642cbdf03996357e4513641b1f8966df2ee674b225af6bde3b1c11d920312056e38" },
                { "sco", "d789acb2176e035bc8eb38a7dabda108508e53fc58e7c4fdca5987cf77bf9ff8e06d0dcc9cec194a1261633e0910452f4a4d29e61e91bc6a69c59f2a224cea53" },
                { "si", "097e4b08e33ac6c6af10d2fe9fd2b68076fd0c40295ffc7ef050f7fd29c71427a98a6a657c499a480d2a0e21c5eb0d1968ef25ed581805e891a667814ead74d9" },
                { "sk", "6eaa548a124637e7700f1841957925160fcfad8477185a9e78f8b0df4d074622357bbc5ea02879c83aadcc437321dcbba8e7b0362a1e7980e6d62f0f6536a1d3" },
                { "skr", "9cc662b7bada9ea0b78879390182ef8436fe8f203d38b856cb64e303b00faf4d8c7d2f21a0a746a0cd137032f2ff12f4652598fb3fec31167447895b349de9e1" },
                { "sl", "221c0e7d92cd18288ec986a834871e92b24d36ed46210c9258933ed995dd1d96c83f04535e4d0e2074ca185d916abd5058126356526f2cf4ea27b4bf125734e2" },
                { "son", "6fa7eafa322e1601c3f0d2f5989de5ebb35fc3adf08c5d05d1245342bdd0850d225ccd8c28c6d86d416591e6c55c9c6030de5985a510fd52f0c1825848b0d61a" },
                { "sq", "2fd5bcfe9de5a327629be5e6c6ee5d1b36c174e3c56ce0c41016be386c1b99853a9cffba6b63ed5bd9bad7e0bba38cd58fa0a00bd6fb45a1198fac6b8b865bb6" },
                { "sr", "1b99fc0048ad6981f3b233dadb253b0a2ea35c8b44d069f93fd4b6fbeb97261599d3d95201970a4512b5a41f680631c9d629ee75e0e680cb229314b3a2b4369a" },
                { "sv-SE", "22dbf8f35a2a858639a3852198175f2b0ff34cc8cb3d6d6983b368f8cebb7e29251f9b395e8421f24ccc85ccfc5ddb3fbcf07e410cad44f5c832b321e3590298" },
                { "szl", "69e7f4a075db46f2f08464fe36c2224b2dbbbd357f03f29f7f1be79139d6d8b3df81988a80e877bc677f6b3175f78aeeb859a713bd40ab47863ee0126b03b972" },
                { "ta", "06b6cfae56955481fb3774748be484861cd983a1f7a4180d3755ce9d20ac6f1741eae31cc963b3f5aee26fa3a97491bc9b00952cc7345a9cad003857bfd4565d" },
                { "te", "44219371c8fa244b31e17166ea701c08a185128854cd89e34ff369bcfb466efbe3146077fbc71dfd36acb900ebf9b6943eb56ab82536068bd9af4500c91dadb9" },
                { "tg", "170e11cee7ba227a19ffc8175bbf06529e016962bffc9449fa9f0b1d16fb8eba4d0acee3665dcbdaff1c1437c43a49ac27ba086490640066123c922d7012b48f" },
                { "th", "3a2cf74eaca7c5282a9f43b349f5dfbd4c93d00a01fa78dde37050fc1873fbf984a6c65f252734980618bbf7ba79e82d7862d1fe8794413c40fd5d84cf3d4cbb" },
                { "tl", "289e72e34f22a786bbd6c265b3a8ff1b9c34352dadfa14927edf363e9aca68538d76978db1dc2bd1e8b9a5b76b3e050228206e2db14288125c26530c44bc7413" },
                { "tr", "b45da9a51dcf0cb4f87b2a6d96de5defae0a40ee730a07e834161cdc15a5183eddc2fefa2deba5d7dd7d7899e96f5c98df20155da13803a255fa4779707d5e53" },
                { "trs", "6179d8e5fd2bd7c46b071be0cd50584ab788ccb41e03b15faaab8a2b590d5f67c04293feb4c50d058b8c72719339f4fd68ee6ca3febe9ec47bced50485db029a" },
                { "uk", "f744d2925d0837f06d13872e34a952360d304b02f01ecfb4acb18157f3b3a901a6ec6c4b9ba3545c7b762f9ce733dbb92e0138dd05119f9450c886235bd95805" },
                { "ur", "e7f1b1eb2f6561686093c1f0c43755f9a5fc34657f05060a13a1d7fbfcfaa966c9c924908c283350aac918255a9fb7d5f0442409377b2cc707e46ca4f25b8371" },
                { "uz", "7bf6ca9d5ec35dad113e3154fa706ab5d9aa4dcf0243ab7b79afffa2937d0e00f0e5a85f839507381c4a55e841cd832170c8409815f04468ded281fa2e5335bb" },
                { "vi", "d14290c965103e64a2ce8434df26b7ae03883f8522e920726ceeb027434721659f6d83a0ccde881c847cae19ffc38a00aea4a500a2860a2011bdcd896db71394" },
                { "xh", "259c05df2cbf3f512dc515e5b051abcba91b37edde8bce3a4bd845c19c8cbe4c930bd62bd85ef9733ce8b8282ca931cc450c93f6131109cf8ad766273d1941e2" },
                { "zh-CN", "6dfe44fccd62738b7b27df576dba14ac59c882aba7c7412a60815c493656e897000935e01fcbb8f8bf58afce5db7569c4d0704f3f981acf0192bcd63c50705d0" },
                { "zh-TW", "47123a4ddcb28101ed214b20fdc2cb15d97e5b29a6d3f2f3b44bb25b0cb2da30839c8644757c1af9a6a444e7f27ea5e22cbffb0e1383d946f9cb84922a46330b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4b2f9b51ad1c062f07d57ef48fb907ce0a9e4021f75bbde777bc858012b40cbe7fd20be92e791f6b4e2b61a9a0cf5683a7bb382c1f85420c40f2b52f01b3c93c" },
                { "af", "e51811e4de27d8a736fe33f3088b619914d1cd99ae3e702aa51522960dbbae88389b3dca3090964e462bff13243aedf0ded4acbb498031014de25dae7d1d343a" },
                { "an", "8759b1f5ea89b37e5e0fa02bbcfeaac058f3a1e0da3b7576380a456f5fd6197535a8bcaff904703ae59d9173e67f23990dadc20dc2af6b0ee83e4dd2721df541" },
                { "ar", "deb803303b08faad2edcbbed83ddee52ee5d092c82599680296e4abb7bf7b3a1180697faf568ad6ec652ad2e53558c7b4826b074c34bed8105a551cfadb47edf" },
                { "ast", "4de54af3d6f6e8e314dcfb27fecd222f62af7f18a849c6c2a9c0d925cc22502cce53bd9d4c6ed8ca92ddc0ae77250d5d8e76d70fad33a67ff0e92ec7d32b01a5" },
                { "az", "694c26d829bc4292de0553954e11c8e963b9ecca240f804d408851287b2bd4077d112a9ff5dbbea3c923927eb8437b292060a38dcbc7254073e27f1b45237f68" },
                { "be", "17ae9ac04777a5ae79773be06c9a8812d5810ce54a06a08d4d88a8df7ba7709ff2328ec62877e29f6b5cde360e5b04b69e6f5fb5a2b7cb0cc6d2fd47f2da2826" },
                { "bg", "12e9b71be27fcaf5b9fb924f37aae976043db432ca460542e5c5aff75550c5da529204a5952dff68086d7a48337fc9eae9c36685de90d1e206bbd70cf6927736" },
                { "bn", "2c1c51f0c92adb47d666a3ad85a28c76d340af92382b9cd9b2aa917c2489d7e3e17c794aba35b89415298a7132365774e9aed94e4a368e2bbff38be811cc0b27" },
                { "br", "f54fc0f48fb765906ff66da743dc520f58a21509e90ba7c8ac85cbb49adb1ac1d56a8c15b61c48e2fc95b6ca1e780d9d95acbd423924317d2a12674ce705289b" },
                { "bs", "ae879c946790513d5ae5591577d630a9918d6962dcc32661fcc2f26b7f376e6f791daf388d100593fc91a6c59865577092120b8256996bd3e549c2502eb02bf2" },
                { "ca", "ff4a7e3299cc3472c1ed1b6c924e66b1a8d6142bc000c11a34a9081888bb7858c0db05e5bff5ecc9255ac97b63867069c1ec0ecb778a74a74e49b8394a9b27a4" },
                { "cak", "5865c16a93f2889d9cbbeb72d44189159336477e6e69f4f00840941454112ff299962acf62fffe474319675d2f3e5fb55aac34ab2788d0fbe2f9e62003258ea2" },
                { "cs", "29d63dc27e91e7a1c38dee06187c8437300316d3a12c1c496edbe01073e4bf0e6a4e979b70fe712c531796cf710320b8ef87f2fc9c2acbe37003ea23bcfab9ae" },
                { "cy", "41516608dacf2e1abfc344b682042b8f57416666ba9af2026b0e6d01e86a0389180415b6b054efda69b50ccdbe351e5727ed04db61a44e4dba9d4d96e276912b" },
                { "da", "68f63acb15b3ec108c1d05301937186452800c8b7e1d512428b922fe32c863fa16d57bf63afade441d69d130d7d21cf9c204283f5a27f0fd9131449ae627ddde" },
                { "de", "694f49965064f2b6b3e525ac7bef284ad96b4359658c5991e0a36e6a9f518178dfa69a745ac67966a75d64c3d42231eb6f8bf6065f323095dcb16145f17d89d4" },
                { "dsb", "4184b3fddec2e7ac8d51204a52c4cbc54b1089d26c2b565db5c0fc6507594b32963abf5516c8642a51a39018e6b3f16a4ad104c27b07e2ba1145dacf26fee0fc" },
                { "el", "addff8512d2b755f853f875c44d6e39ba6a418b0de798b1f5708d80723d5e08082fb35f73088ced5abc2a297f3f89557b2e1cfdc535ec1eacf0798bd5e83a5b9" },
                { "en-CA", "2b5d369af6c72effbb4a90085b156026dde27e12ada0b3414c6eda804ae57d631d96f047d21ad8aef8cff036caf735064b9b97372f332d19a35a2abd7223a550" },
                { "en-GB", "43a13debfd35b3de4ad4a074a87bc71d819aab32bc6d7af0a0ef35e1c3b12052bba083c8498747d11ac88a4917cbe6864f6f8954f60d29d3f1d28f3cc110c376" },
                { "en-US", "64666ab5fe139d5ee9ed805bb06de6d37d2db0413eaae676fbf8257b918c02d12ad818c5208aa2d4ff7552b0a6c6ff12218579ee35c0526e6a4943845048ca93" },
                { "eo", "f031ef2ad09ed51c77c2210ef4b1ae4d15f0afcbd1342a62b8f14771c8035b9e049dbb385c8f953ce53c9df9cf4eb955d760aeb1a16bc930e29e02899c343b78" },
                { "es-AR", "f00f1c31dc348599f3998c1ce7ec4c30368204cbefbb58a9ad4a11f6011bb05d8ace04fc2fed4be6b4a6fb5d9da5eb69bd6ec9979e4cdd4d6b2aee9de11596ae" },
                { "es-CL", "6bbb1d933f3235374e69cadaf160a435949c21988049897c22496b3b1918366a4733fed23e9a1b4bf9666639cac2703866cbf102700ead22e4d339ba219f734f" },
                { "es-ES", "e447bc71877efdb6632ecd2b5f6165c864c957b21aee60670ff81c5cb24df557f6bca9315a907f9cba8b647a92fba8c54afa8d63ee752f98211dcce183900d0a" },
                { "es-MX", "7d9331280688bc9c6a6f61fd93a99ce945759655d31e7fb53af80b8ecb627f47c6e93986471938a3dffa249e625b2f3a0979b7c82eb79ccdc4cff901eb0bba3b" },
                { "et", "9921d8b34c4ba4953bfb2b6ef2d328fd73580bbf894be052f25b46e8eedb473daaa4ef4ea7360689f9c818366eac0a3b23b0b21072589efe30bed1784ea2aab7" },
                { "eu", "ae8340b94ecb4bb4eedface12996a6c0505f2969df1df913d29a0f930aebe630b2bc52ea23bf3ebe2e3e5f89b066a287c0aa640c521e2df214517d0b1ea369b8" },
                { "fa", "f9558b7c22715335bf74b4da7d819197e56cdc26e96e3bef67306ea17992cb542133fcab117d740536bb350f6b5011e47a9a1923818c7649cdcb684c6c0b642d" },
                { "ff", "89d316de30a1d93ff17c2ea35025486405b53e9368913e813492bb46979e6a4b279fa70a876f3b4ed5c33b31018683aa50ca61e2fde5e0c2dbefb1cd0007d99d" },
                { "fi", "577ffdb01238e57fac6705a3f1095cca10c7bb210103fe0b3d1977f5776ffca7baeb9f67f77ecbe859dba8d141982b7a384dfa40f1859ced5b8aa0fdcb30f64a" },
                { "fr", "3cc6631f8431fb9f0e4f0d709233623a593ea9b1708ba620b6f177b20731add77e053437b3b2afd74807cf3f5d9d07cce51dfb243cfafbfd22acb0a3644d616c" },
                { "fur", "322514ca2924d44b9cd5be7646bbe8750c7cd3d1db71d9cf4cfad2a7e03cd839735ea05b2ce83e7bb9f39ee8a9f90abd483488c3b558b41f724019a322f2cd37" },
                { "fy-NL", "1570bc10deebdcf38fbb6a94076bc99fde1686695892e1ca4fe054586e4759b1d8d74f407cef32350b49695bf80249b5ef3047a7798c8887c13c47483dedab01" },
                { "ga-IE", "1b494e74b608a9aae0a1c27a04b5e0327901b7949149529ebaa93330c08b280db2fa2208aefb4b878c5ceca19b0c8606d445cc5290e645766dfb17e8b035f0a4" },
                { "gd", "44c278ba24898fee3df7f27ed98c3fce74cd836eb7fe194ef980e5762dbed5967192df4c083fb0597446b1b0fe40770f842c629c6d1882d55a4ab66fbfc0f0ca" },
                { "gl", "7c67fcb8809ed88d7d5dc3c526f9b3941f2541a2941a1287a1edb018ec41ebbf6c45b508fb0a9bac80f5f57a548722c4f625087b756660404ebdc0cd35bfc4f0" },
                { "gn", "b172f7b94d8c6c42189b5592cc5918e11ea731213043aeddca8482f4d748be6482a8999b1402726691e0968b4889e86166d79e870d9ea641ced69844d3e8b85d" },
                { "gu-IN", "bb911dce8d5bf78e48ff35eabe58978af8484ddb187744aa251804f9f80099cd6f434ec0ac47de293005e8c1b042d5bc83a07f88aa8dad45723ba0c991443d10" },
                { "he", "11df2337276a3bc5d3eff35d4ba17ca1612553ef6fa394cedda1540407cf659bdc1f98bd0fb1c918a1c8e18782edfdcb1211dcb49f8fe66aea1a687ae892bd37" },
                { "hi-IN", "cae114a5536f289a5d123904137563ec852725e6c932dac9c7829ba111d68e4813aaebd3acc86f32314415d332d33e708736389a25742a6e266c2c505e1c4ec8" },
                { "hr", "225267be7d01581c20baf6466951f316900ce94517047445b58e3c50fe2e010dbf29e19fe52790537e5ace71011b208a8ee76b7e813e536c38f9c641ef85dbad" },
                { "hsb", "2c7aa063d090304ebe660088a485153780dd536d12eecdaba15891cc162e2a0065a5b908cde80d4e3a219da45c8756e6dc52fe89ec24b706fafbd0e720c7ab25" },
                { "hu", "83fa8eacc5065b2f61db9860f22b9b50bbadbdab541a63482cb5e31e6dc359c083a99b7d29a4c388138e2a9445241d4401e93251c448cad7d9e2a3b391c97488" },
                { "hy-AM", "db7967708d2bbde3e2763fecca4a51afbc4d4de99ececce332ae52aa931424d0b7c4c76921f29c851c87324a2caaf82db0bf48f0ad2544fa7b25865b0bc36827" },
                { "ia", "d58bd8556ce4e9de9274d8ba83e3bf5d64e29627d642ee63f3aaf9305c93c2eb3fc06f3f6ba1431024210c6558ebe44272a100391e1d1abe7563886f6b992253" },
                { "id", "a45cb057ea61fcc834d13caa48ea2bf5bb753f51c2a08759c435111b665342f8ea1eccf213ba7b371d482feed5b62c550a55c05e13900b78ef390b6f6160b222" },
                { "is", "5b9f57962eaf2994734f0833b2ce035be26e111d8ab762ce30061a8a34c5102aaa58eb4c6f7b51270c040026f5b66172ffef96314829cf6af16f13817192e239" },
                { "it", "c5f3fc423d523836d9248bc8e1a8a6b1ddf37ce97ac7d4a54b1535b0b331c6b477f560d344c41c775184d3d062f950c32475e4dbf0f904b9d23bdb5ab3bcfc2a" },
                { "ja", "d450d8ce129bd1abfa7aca0eff9cea8adfe7863a0b0edf52a5d25d185da37a1e660f58b450071590e384e3b74b0432555ff883d217756434cc24aaabdf16e7f6" },
                { "ka", "1e8c19fe2f8c546889aa5960f8b9b83bb61614eb8453111f894e5a38d0d21b5e570bc8b35086f7f71aff5efd3b0f4b1f242a6b620b47d924e451927aa59ac720" },
                { "kab", "57ff5ae61a69e70455b288e0eb9600a6dcf42ef41efec8f6d8405d3fa77a84cb408df87ed340e50b2f852108edd5f2bbbb7ef99ec34e6c91904a4624a33f8677" },
                { "kk", "fa4bf876cacaefc23b7d2f6cf63c28785f64e682882d2fc81dc297a86d056c33b3d0faca3c797866723166edcfb698af54247f2c5a9c7cc19196c88d36e05d0b" },
                { "km", "a8ad7d6cb544169d79a6c31f78b6926419da93ae494b8e11eba6a1ea315c9597f51b3e4fc24170992633ef1b0cdb1c5f9db3722058769d6f95923e4f368cc475" },
                { "kn", "a87c53b873b0c6c520782aa55b5d004cfa460e9be013c532d446027dd07d0bba6049f155a80dcf314d79daf3d49960797623f2a0e092d3ebac1f2f0ce36b14d3" },
                { "ko", "5495ca88185bf7f628b0e6b500727ca418e8be781e7bb87c5770e732272071ec8cf7ad365a46ad989ca139c49b47a9d1988e077fba5e93da27df0cf05f3cd763" },
                { "lij", "05eb551765516ebad0bb4ed4f76418677b8c387cf8c63fe3cc1cbe6699040789abf623c1bfce1f5706d1570503fac8ef7fff72c02943c2562406cc5b6f6a266c" },
                { "lt", "28174e68f4bc78a399c8316d26ae6889fbf52e56a2a5da760369a01d172e2aa213816773964dbe3a2cfa5aec6403521149e789599a2d30af6c10f3e3013c1215" },
                { "lv", "e2aa59f2a006e219b1fc2ab889d2ef7b3e720e6d8152b73666602597b38253da79dc8056fb6e4cb79a04e6b2007583d725d4aff3b2d986aa7d5da891ad77b0e7" },
                { "mk", "13ff5e509107c8e6e59fe937bb0d8e59ff9262c63fdadc3ac64946431aab2b41300337e3eae94172902711ad80f536699f0bf5d97cd1da29d9c8cfbbce9c4401" },
                { "mr", "d7ad5fa98386bf685861ed282a6dc96f3c822e895b9f8097467b39306bd2dcc09989674fd5c26f2542358c3d42a9d56106723b5560dedd5268043d6f71505858" },
                { "ms", "f9b42479b8cfd981f28f1798c5c30c5bc3714499bbb1b7f769fbf6a1088298ee266c9869ff344e32636012b63e5beeaeb9be174f4591d721af8bfd1ebfe11f89" },
                { "my", "a4762083ebcb11f8127f0c8fea1cec072835378dacef1696d0d8034d2dc23e950aab99944d5e8fe33a9e2b20d8cf919beebf4e6867512a42f985e30fb8ff24f0" },
                { "nb-NO", "b087be49b6d4c5624e8477abe1fd46b8758a2389c2ec5370ca333835ada125c4bdb3d98c82a101792649b55d49739d4244faa91bd35259e87f8432182f43ae3b" },
                { "ne-NP", "fe9811f26e6c503c7cb5a7d52737adb1bd6612e7092fc75494e1f97e28e5432dbfa3e41ab583d5b0c9efccd5c97f4e30e6769ac7281101d7dba1c1ff17bf820f" },
                { "nl", "985507416cd882365f1d69e2f93f84dc55526b2938a16b652149b3eace8bb2cebaee513a5f5106474845e4e54b3832e8202d84259f4ca17ca1c7db8124b65f50" },
                { "nn-NO", "a8696780df829cb3f7c800c3c2113988aad114de4d5c956b20ef58ecf3eb0cb77b547da509ef9574de4182fca367e8f746f6f1519a72a344c728068e4eb668cc" },
                { "oc", "af59a523d7fe4e5a30f9feed3d2835f9477a3bba0d385ef919692cb7049cd390f48ce2ddbeaca3487cb62a20fc9ace44baaa118e01b03189f29161241910fb5d" },
                { "pa-IN", "5abd6d9b2ff422b3c1e7311d4629514bb8a5b6ce5de5536a24051f29c36996af0d4a22a00fd884969a3c2719eb70d2a04f9e329c552b0757961f8defb0b6f0d7" },
                { "pl", "c77338a87d65b5fe3a2826b694033b8ef6c8a354c135136169a585c552c1e66ea7b80fa323f12d83798939cbbafc6724ea4c2c98795333e237c2b95d1144d299" },
                { "pt-BR", "c99c782e550cb29bcfdeb2596db04d57f7356e8496cf768e090cf3e1362b484806a5339af0fb487032919f4f43975f55c8f0dd4667559bed5057fb38955afdd3" },
                { "pt-PT", "569fd8cb95c3db629814022af1d294bc8265dc0bd12fbe573395d5444edee626ada5be79a4567ec661541248d334b316fa4e72259435002c8c070d9894479782" },
                { "rm", "de3f3db12561fa3bebc8655b28579e2d851547a2752307a9d9aae177fc3a6365fa429bbbb7ceeb3ed307c05ac44332cb846974ee891448fda4ef824ba660a105" },
                { "ro", "757006ef0b673a8539bb43fc7837113e0af1e065129680b435d4363b06b063960a04a65584c52a1ea6f3024997a02790e6808c90e9898cbb7ae8b16715fb9ca8" },
                { "ru", "ea7b9e6f3e5fabdd86a7a2ddda5ff9f9b9f8b7a90e7a6ce461efa3a85ea6846999945ea6f1365b1649141329f8500f4f642d0758baadb4166609dc2c3d26a28c" },
                { "sat", "cecb529a044b7f7795542aa5453545dc43555b640f50360b7b37ff74e63ca13f3676ff8ed4bf105e58c50ecdc256314c5a97472888ced302f2455172bf038d74" },
                { "sc", "ae08feb6aec66114d66dc227c2f7026c799b82bb54e6971375e824289c842e85b5fc23fe5112cf12759761baed0bb97fb05c2cff23ded2d11be84bc5a45273c4" },
                { "sco", "7f2db56eaf5cd5deab40b38b6f978f5a145339987b6a2213eb5ca550a7e30f809202b6d26a37c815587fe5567b76d5cbd8ecc667e9654564456fc01763772725" },
                { "si", "b54243a311e20fd4fd727b10b509f59a8096b89f8b775ccf27144254cc7e48b06891ffe4826ee351d41cf5ce4eca10ced308f7768046761aa47546e6c0482072" },
                { "sk", "ae9b627e96895065a6f6129ffa92a75aed81cf741fb7d05f327205cd2a6b848973eb72ecec7b1649edf42a1ae4253ffaa6bc8f178d128be1c947cfae6fdd4a1b" },
                { "skr", "9b4b365c24b19252b154f4200b1d0345686790129f55bf5c98298141f8e6f5e2420a182b9c437e7780da73b02258a6161ea1b646940e3a4869cb3afe6bcfa9f8" },
                { "sl", "17d50027904f6758aaa8c4534a255b7e059b22a584339cde9798b378cbec607a6c6a4d4d8cb04124932b699b47583477da8735d870869deff42c9619f804a293" },
                { "son", "e41d4a4a4b0e42a50a71347ac1085df2970ae1b941b8b6647954b84c9e39347e49be7ea6cf2a1a4b843ad72804b13a367597a42bc3603df72f7eff1afc3526ee" },
                { "sq", "1fed43177d77a10269671970866a9a583b0d89d3355f83dcd18da131db952a7f694fdc2a81c182eba027d512b665c7ef4884c3290b90757193a05d21f6126f26" },
                { "sr", "2a51d9dad98d063d9f61ffccfa4aecf84f9f9929e46a5acb848afac565e85a0302c82f3d61d668edda2b7777deb5403f2a01a624f8d0d9f36f7d1c8601b9390f" },
                { "sv-SE", "e5d3067e230bac2596dbcea5d797030a428a289df2dcc7a88ef3dcff7e5b606bc491ab61baab7cd58ffe71ffcc66c9d5a20a58999f48998a75b4b223af109a3a" },
                { "szl", "f7678084ca64ba215476c3789b18f8a2d31699a9d7a55781086ee3ceb357c0ee1833e417514e0eb2a38320691c69474c9f894d267f97e5d4a46c79b5c5c9d320" },
                { "ta", "d5d46dee0b4e0a0f6a477003926caa33bd6d0a79bde61db35199da1a6bce0361290b5e7e61e05dbd27588c9cfc922d2049278605099c0e29b4f6dd917bd9a712" },
                { "te", "b5dbc90dbca36d6c06589bb711c6e090df72d45d92b2aefd1e394a20f93a9759b9fe4ea642a9b57befa4f38c832cabd752e80c2ef2729c54b5b3849231521c5e" },
                { "tg", "81e30afca5a612641ae679a215019d8a1af6d7ffc7583a607850de6a1d9af2059969eb83446d2b83cd356fc0e599c8929f5a85cfbc7b1c478f171954f75202e9" },
                { "th", "11924cda7cc269fb6c99f91f86d8a51d14d590045ce731343190659ec2519078118962b9cfb89b4bcf50b857904882fb0e3916112328a623fc5fbdae1d633af2" },
                { "tl", "5eb2be8ecad90b245ba88ad581ed1cbd517d703a9aa75f1d97ceb9401b9b84f3ddecb8ee0226354bbf70b9d97e784ab0797f6bd81a766b765e2b5436b2229245" },
                { "tr", "ab07a4ba1f0d14b87252a0288bf6e7cfb2305923ce9048224940fb61876b6f4ba91715fab6b9d596ac81b3cca6cab4b0dd4cf2ee6610f9b69f4dbf83977fcbc9" },
                { "trs", "92f644f64c75dbf796ad4060bc647c533578f64e37bdf9ca5a89ac4dd76e9ee044467bf89f71c473097940ed8b6c1ebf805b67851224e2d12ba603dd99dcc61e" },
                { "uk", "eaec85268d30cd199205016b3341202021ed1022b82872cffebbeeb33755e380434db7b8c08f100e49a57cb180380026cf51c73acf5f3e32294b86221805882f" },
                { "ur", "b487d62ae2da28ffffa44617dfa34f1173c40317a8b2a1d5d49ef0dbeb41865efbbd931ef439a5769159c93bfa3b0088c788ab5540e1daaf64c55ed87e06928f" },
                { "uz", "7cb6fd477f8c21fc9cbf1fb2026dd65de5062fd10a683377e468c7bcf0c5f088b0dea60e1dfee9e6edf30d58451ac5a8ca940b939e77d97b701e995d55cc5a17" },
                { "vi", "eea8f2f18b84b68dbed485894252401dcfc671a39188970c52a93c7bca0c4ec347adaee42b14d518e49c98792af589d66d41bf62688b30c9a3299ed5e2d91f55" },
                { "xh", "048e694f47ece1a67887f5535d77a48aa21cb424ab1f19eff3678bd97789354f94a919fa776183a38bbcd35490d21f2e70258880951d28fdac2a31bfc81c9e0d" },
                { "zh-CN", "f588f8a01655b27be5715c9a64f6af533d7f855869e42efbc198877895fcc92e6be3aaca02f2e6757cefabe17c14b7ca6a4695da2ecc919b9bdc205722a79d98" },
                { "zh-TW", "b87a9f78eeef46049a13cf31edd4285e8c3720e9a0b89155e4634414c66614383288931d4fb7198873c249a4c3396485df5e6c2c145aa7c74a200a6569b7c60c" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return [];
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace

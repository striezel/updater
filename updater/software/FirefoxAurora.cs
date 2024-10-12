/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private const string currentVersion = "132.0b6";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5d59788e9a0fa432548ce11d4218517a32a19ab993b9c58aab69be5229a865c85686719946d3a40f24dbe164dff01538f79aa3274ca33f17a461056a40b63e2d" },
                { "af", "4c0590610e561150f167f7c8e26a5245556ae614308cbb26f366e71b0e5def83822c0a3d88ab72fc28594146afab3a5b3d856d62c907c10b9ce2aabf7f054d1a" },
                { "an", "b0a850faa665e2cd3838bd688c747fdb4ad5a93da6faeb5ee14d7445e22df6061c6078fd29feb6b90a88c3550f1f04ad5a5070504d04dde3bf06c7c9113ea931" },
                { "ar", "5fe2ee6571946366d14980a766e222fdcfbf84657240b6b2ea1d43a423b562e535e99bad997245ef8e815cf650be6850f7cf39253508414b82f7fd73c07e096f" },
                { "ast", "2c54d2f7d3b7b705c92c85c3253f9e54a1e12ec6ba16ef63343afc33bca8abe4393591129ee4f8f3f774f0e719122a94a0e66a3f407fe27c145dfc40149c7a1c" },
                { "az", "c5623f5aaee3efb0919a3911dd5dc39fd437202241814038f3e1181751a64d45f4bae95e5ef7773876312305d89cd504dffcdd73e628cf5b61ab88724a286b02" },
                { "be", "2ccbd94134d59fb153f2ba8ff7af0fb6f4ba6454302b2fa590619c37f5085c8f31eb9933f53ab91c533f47aa46f773709d6c8ea53e2523401b342add4a996d39" },
                { "bg", "1b6defaf35a3c351055473b21dd6af64f67d1d9c1c4df336ef2840fba1e931c58029ad69c8f5586dd158ab0fb5a34713c26b6ba9d6920898ddec42fc5f1678fa" },
                { "bn", "12ea8cd7e307b4029f098c4551733535c259bba5acc7b1fe8d5cb94cdb5c02884253bd7eadcc3a35d12ec12ef97cf1eb7340943936c1af74538d6186bdd75f74" },
                { "br", "cc312d1d7a7b04bc1eb2d3bcc3bff192904f17355bb8ad715893d6c16a81b8bccaffc98eb3b4652a8b7b83e3cba8c71b248f6a6088e72eb8bffe7f38f4d56d40" },
                { "bs", "4163dfa86043b1b7eb0c9903ef8b2557c1df5512aa226cf83542033c7dd7774ba3e2515a3b8e51afb3b8d23e2d4408f14fbe0db4ca116ca7ccd21427a47e2416" },
                { "ca", "ea1348ff072b4406711eab2711058870d229e475c9b358fc2f6dcf202b74dc27b8fb16e2a4f2b3e46a53ab0e3025768a371dd06731ddfe4dc5875ff0f5888068" },
                { "cak", "5fbc9861bb120c328fa769bdcba2b006514a82f2e66cb564304cc45cf084b776832a5f2c940b52cedc98e61be6d7457a24825caba56aac63203ccabd66b98925" },
                { "cs", "0761640ae2cfbc424dc265d18209933b7f88d1e02dfc083d2e3b02d21f41daf166f801215f725e17c68cebc6ba9d16161830f21761c04d7e6614f28416e3bd38" },
                { "cy", "9745ec62167a950bcea43e3b70778d5a531ae9e896b78399a8f90bab69a93dc2b6b747d7acae939bfeaaf4764bd84097a48233ec9a541423857c6c787b9b33a9" },
                { "da", "4ef8bb3f2b54f5edcc3fe838bb77ce2b9bb8c286ab2abff319eb3b2b4e45ef41b266580f39c8c7843b979de34c84cba62b08ee73286efb39bdb0197a42d92218" },
                { "de", "144fa09737687c32f3039f5c676b518649bf9e7424a731d61dc88dafb87cb4a317689682ff611faec0d59686228c6e58e84bc2ef29329b9659601db5f2b7216d" },
                { "dsb", "1e4bb21cbd5d84eeca9a23bcff1c431e7e73e9492d505d7ba06ba757086e0cf833e7053277ca0c47397417e1181b67d00c8c0c9bac02040403dd574cedc69533" },
                { "el", "68a4d286b733cb90d4b16be0babdbcbe7db0d1ef1e3271b654ff16fc1b33c56336506c4d3d99b6a5a3f997741d5d9597fe45f49caa3eb65a421a35b05d727c8f" },
                { "en-CA", "9dc63197294c4fd583d9ae65d99940b328fe389db97d1dd482608e7d36ef5ef91cdaf03e9a871efb69e82faa5445c63de44b792502f1b0d03531df09101de838" },
                { "en-GB", "93d7f3651ffbb1991ec0bb8f73600ee34dca6860afc4f35db35c16e5ee462a636232738063296183a1df8051e891f9dda37da1900bc1fe4d90839ad9edf5a4d7" },
                { "en-US", "19c1670567b5578c30035cc9d5d167a7379036df7ae7f6a001808951408209523126c0a8cdb8d4f6893aa42d1fda3d025f854aa5e407549c6338bd9ef2b89ad4" },
                { "eo", "072c06f64f5cdbfe41727d678de2f52d1f3751ab4c2d56131c7dca99f6e4a3ce233e5e409e7b162c8b3bae8bd489e583f2323520ed65906fa1c26ffa394b4f1f" },
                { "es-AR", "5310f6ebfdefc44145ee31af5fba7c8be41900c0c722cf5b8afdb4527b7eae521ca7259b44efa995756acf48cdd49fd70eed8ca2bdb0ad3f9a4a2d4f33861769" },
                { "es-CL", "18497e224251e1fe4c607ee4dbb4a49fe8a00a473cfaaf817b279e1d53ccffa999060d81d705a3cf177794ad108dc9359ad91bbf339ac70e21d78114a35a06e2" },
                { "es-ES", "6333eb01f40c6b394a89f01529f985e29f54ddd0eadbc77cf2283213ed0b0aec794a04051e750c64ed53f335855d36619161a0a3643d2c292c52d11c09c65c78" },
                { "es-MX", "b5571a59e977d8613e1e933c56d5e71f3981ca7c7f6809761ef5e55d26c6ef4dd9c26ac1f5a702b70fa97e29c2576a8dfcd08e051d07681a66723708d5240220" },
                { "et", "b8e6467be703c749364c711e6b333fa8f4e84116c93d09e26d28d6dad3860a2e60ab51bf060e55e1767014533bf5c4b33878de7cc16ec11dcbef15c7132d9e2d" },
                { "eu", "e361f2da9dda07248edcdcade6f7ac8d2adde17b3354e72253443149776dd8786c7e8e8ac41da15dcbbcd46ffa56feae8ceef932c11d002f466743f0600f16df" },
                { "fa", "1eea92f3751f61fa7d0a5b31d3fe4d3543a9ddbbe4dd3879c86c3eacba3ad392eb3ebf2ea2da92075eec056d30969d72096d81b8c4c8ae1e282c767f5e565514" },
                { "ff", "dcfd83dce84972851656c3dc5b2c6ed89788c7df3b8f58b5e48dff7358bab3cda2a30627f91d6a61fced188c5834924b8afb3dc4cb2960d2b304af2c35a8e2ad" },
                { "fi", "9ac0d5ada41c918155ce626ccc64789c9c716d8740839723c935b7c1f2d822a400e9f5bcb22090007d4bc3a3a2323cd33516618ecc2f6988a2ca02c137bed1ec" },
                { "fr", "327cbafa8e7c338fda4e7edf27265802c1f5251d82113874b62126e0c890838340b70fe01cad819e9913cbd9be2cc20c9d4acf61acc727a35a589fca1b2e2c7d" },
                { "fur", "3d7771dba17ffca7f29d3add7c6728a1ed68adfabc1c4a272fca1e0c6f83fd962000848a4de67fe6c45826bd99189ab0010ff8d71f6ad7b4ef52268093bb950a" },
                { "fy-NL", "bce1ca99c58770769c8b2fe9577cc830a6de2662af6c9a31584cb877b42b2b9ef662b6fd00b7fbb22a380ea7289b479af66e05f3952f89e5358d819910f72f69" },
                { "ga-IE", "e10426c897f9c482da2d8747586ce4b5e391f99e7d4dce4f6448fabcdeb3b8ab651995431ee9a04cb7523b946ec9facdf0c75f10feab89aee080f5d6cdd98bbc" },
                { "gd", "e352b9a6ba7bcd4321ca46add37b901d50b6236ef9900a796e0f0aa2c42c0126275b5cd6a3fcc5ec314e0cb9598985c202b3a33465a03087c251cb6bf672f395" },
                { "gl", "f1895ce54fc2429a2afb7cd21f601f5ab9bf47239e4b0b69ff7abf7fd9e76d98ff15aaaf27c0b5d0b70ae761cec9b1774b592c263e75a25a3f19936ef86290df" },
                { "gn", "23668adda84008b5d40f5dacecdfae1a0764f5508539610703c59736e0c2f8656216d44b5ee9b28500965a2a1d6337ff10e52cb3d0585a6c953e67c312ad9e69" },
                { "gu-IN", "a4584da893d823da3e1211ef5ea02addb32c7a0199421372a795d3d628f18150aceba441acc28a699c0231d41b093ef32d126ae70701664b9f0d305a6b25c260" },
                { "he", "fabe4d5e0aaac2174035316a929b78925c9b09657787f0634e0fc37524ab2e22a2a4711e3e7b0245bcc0d957a374c9d5dc309befe3839cb640e8ae0012d9c66f" },
                { "hi-IN", "7386efac172dead538abc7828991947adfeb4968ebeb5f86a5852b0c3c353972534e75698ce4799f37468b2db0c6056510331121297c035c4ee24a0aaf532ebd" },
                { "hr", "028cb5b7ff97967aaebd5bb455a900580f82f7e8def716b4364b0f3aa1e9b725a16f275e42ce0a973ede15ec793c67cb7dd499f073199e42f8968686b194d745" },
                { "hsb", "8e456e35c1f89dae7d69672a2c215bc7a131f40c2713dc9707ddb72a68ffb12b8d60458fc02fa024a83c134fca759d81bd0e00a73ea42cc3dc7a53421821648a" },
                { "hu", "8942b0546f87f3f483f2ee20358c744e70720cea73f729afbfeb29202e93549c9fd150beb505131b07f981180c1c957f24c40c133809f2c5cc5745ee47defc35" },
                { "hy-AM", "f96942701c384da52f65f957b9b5604462e8a927d8bd67bad0d4b2cc0332d31c7eaf5503f3e1e7df361537ed37dfc37f73bc708ddc1f1a812456f029623051bb" },
                { "ia", "4fd9719df350dd5b2707915c266b00701d4a6923d398b822904962a7c7db227041721858f429d475fdae61aa6bbfe43650b3796f22ff0d3d52647ec6933037ea" },
                { "id", "185ad99db80f3c7b02bcd62ebfb79d324a52da1f914b693b6322017d7aedd0831a7cc9a45c6a11b6a370ec5096147b9c0a6a5e6caf059fc26f219f034a046b19" },
                { "is", "8d4f35d3c6ae4b0b2508e1ca6adac176dc350f3a1c5a1f941ecfef158855e41e7aaee5f63fdd17df0881c7edb64fffacfc0b28ca42fd15ad341f33459230bd53" },
                { "it", "f81aaa2a2a33562c72e0285e7d163ca1f2dce625d4fc624f5fd9c459e4a32f7344e79e3943ab0af889453669f8b0aacaad521f0f8ac8f859c5f748b0b04b90e4" },
                { "ja", "839cc8c0018f73822a37e6ca0b8a60850a904ea0166c3cc9efb31b60498106b0ecfccced3ed1df4af07266e861f46276dc9bc0bce43926e0a2a83fa647cea2f6" },
                { "ka", "4ee30c947d6a422228542bf33891a908915c658212daccea3ba48f53a8b67fc4e42985e7b63e0840cc8267996e3c8260a7a900657fd4cf64625a48312b8ac090" },
                { "kab", "953db5e5d02b164f0f68bf17fa060dc98435617231b3d330e53db5dfc22c9f39c5d834ebcbbda60768cbcf79d35088c675508a57cfda68a12072f02ccbd4d47e" },
                { "kk", "4e724822753a78e7a68d38720fd1ca066a447b459dfe5801f188ec18588daac8b93f11059e3bab95955755a6e67071ddd3d0f9f77e891f437b14dc78b8b23e2e" },
                { "km", "6444d45acecf03571e6189528fa91d8efaea4e19fb510b4e4ae2f7ffbacb1dfa3426718989d86eb433ae90ba07305cbc2a1d0b4df94214ade0cda1f1daf6dbf5" },
                { "kn", "05e1144a58c4f2cdc26e88f191782052c190a0dcea84bd3aa26a480bec4534be1dc7fe9ea0734e190c7c4e6fde14b79a3241f0fa44c1390d4b0f0af99a156a26" },
                { "ko", "e9fbc81f7f34462e8ecd1c21476d234fa0baffa80b5a03844e24ed3daddce284f7f593550b4d66d182e03eb182cf7d4dd2de054ab0388d2dcda307742f89f9df" },
                { "lij", "c8aa7635e7f8565b9c03177128f1fc53590cac9aab518f1aea1eb2085e23c19ef28a137182fd05a8c769fed69ade70acb5e15af87dd52185ab00fbca6a40658b" },
                { "lt", "ad0b18f9fa960dc41ed7421dd9dc69ecd260896d206e3a96998a2e09ffc684c8db61746e677961623c3c0ad52b33353f13fc87ac77c7fc2d2336643b6b848a7b" },
                { "lv", "d05c1f2dfdad62668853f4190a862c8e7b280b939912150c15b093fe30282bc2c18f05dfdd4ac73fd88a9cf4815a62ea99b49b089d457ec6c7d8d8995858aebb" },
                { "mk", "c03d56b37a5b9e0f7b0a2deaf8251fd0283a8149a1e311a6d2b4ed225c01116d4b287cce9f82290b5b9b64e71e8a30e56447b7bd21c970e9724c26cd057eeaad" },
                { "mr", "c95fbd02a72e0f0510aedb33eb3f45909f0f767ca6549693fd2957dba13fa2ff69f6153c301f1e9076a06e5e2bfa887974312ceab0345256adda1776fddf4145" },
                { "ms", "2a7fb5ff288f9676d74396ebcb804bbed961ce400ca58c71e278dcb578e28ae3adf37e290b7882c21bc390c7d73711d2130a44489a221bb68d8b16040b5fcbcc" },
                { "my", "6d77707af4b1684b960b1f7b382b45edccab127ec4632edea1412f02f872cf1fbbc424ed61522b57f2fb79bf4d64a6fd480baa1bb2a67b8247808dda861f6f7e" },
                { "nb-NO", "b414e27d780f4f65c5df1f74cbe2159c6d478f875fa90b45be2a30a97b702dbf5327f6c5197981a503e5d3a07865da2fc917a080eb5aa16a9848e15ed383f5f6" },
                { "ne-NP", "3a9449c8fa796da7d8aa505e0fd5ccc255b449d3289c087c8af57f479a77b7ec87cd2e12da6988dd53b3ce7d3346f863b78773e21703cfa8a175da296a30da25" },
                { "nl", "847f88a9c6f768310a08a64217bed92fb634d012e921b0bc55380a4d2f39675e4c986a25f3352d3b60bd3801a58874f7bee6b6905155e1066c0bdc35d0e29874" },
                { "nn-NO", "195c125437b43e5f0a901056dfeba9fdd3c97039b248784c019c5a8b8cfd0be187f8dfa2e08563ea5e61c401e8921a3075049acd03f0768da92164d2aa1450a4" },
                { "oc", "0d43205e105ff400b4140840ef3a0626fbc03e779af0a1f0e3f1389eea858f137339b00b1feecefefa95afde66f50661c7255df2f20d4693ed27853460132176" },
                { "pa-IN", "6100f11e01588be8e4ddac920ded664f7a4db58391aa6848ecd735504e170a6e87f7d060808eb31ffbc66d2a13200349e71ecaaa734e352d363bf8ba922bd7a1" },
                { "pl", "66dee5366b5b08bc3872a8d2a258fc6074c03da084366c44487933612f1ffee444f2916585c0530d355314f0af7698dfe63ef863c515d594391d35f62903f881" },
                { "pt-BR", "4028fd37a1dfb027253a54ca9bcf7f5b0adf66181cb6596e7a7848b8d5b59150d7d36dc5da6769baedecdcf9f50def28409b2660809ce9935ca885625980b50a" },
                { "pt-PT", "e214add1fb7608fc7ecac2184f5559006370cc74a2678bbb10c1b89e54232c94fd30b529afc4f15b248895b45863b39f07d2832b849f377ab34e3264b0b52e81" },
                { "rm", "794cfdafc48edafe8041682211c52607589ca46b84802c2e85f5187389568160dcfd6446cc12187a12f30068aada053e0be0d1995a713adafcdcabe1aaeb796c" },
                { "ro", "05bb515c485a0bcee2f9bd92dfc3b3dbf8d99385ea613589d23e9f9f373e43aabd6724adfde80b86d985c2846124e3a92886c6fdf5b532ea74de8cf9b4ba4dd9" },
                { "ru", "bb60a15c91cd2935843e90029dd614a00358242f042c6531f8994dcb0df3b067a64696b76221faaee05bd849de1e963eea240d0e4b57817a34ac5b58fbd21007" },
                { "sat", "f6773ea911b272fd6b2f3f95ba1243f1fd7aa70f3088d78e78682393ea4855c47a050b1ee326c9a1844feccaa6e77bc91f6208709affba8530a26bcd557a0608" },
                { "sc", "2c39794b9f2d7212e48a4e6da0d41f07dd2ff5c6516216dca93c2bdd063676a26bc7a8ae32503f9c13030ff2dd829638d00a78e2fef56c00e0f761c3f2122ab8" },
                { "sco", "051af0292914b4de6797fe1f473ef77aec652a304cc795dab5952d105f1b2ef88116d744a494d831e7dcbcffcf92d98d92864c5d9020e3fcff4d33ddc112ed41" },
                { "si", "26faea7d9cd6740b1ca0bd828bf213fd5034eee1af9024b1c8afe60fced7e224444faf3c36f02ac58a32b37eefa8039b50e2d715e6f2209f2c5141db0da99f65" },
                { "sk", "f2e3da620dcf268dc68526f33d2f7ea450ecc74efeeab33e660643b05d1837eae76e7c446080f55e4ca4668396d4e0ec53269617c301bef2ad72eaf10d7fa194" },
                { "skr", "d85819ef7455c267a6a7f0abb508ec7289d7203cd81e0affbd534b050e8a2ddabad71c272ba89971903f5a333f79db63386d4f2d22ef5daf2fb1ea4855877973" },
                { "sl", "19258b4377a60288baf6a851e0419df1b96ac3eddb7db8681590c7b8890fe5edec7ca02171063c160b3db45b39d7f11925b2619a2546ba77eb7cbedf64f3b6ce" },
                { "son", "16c0913d2c6141a44dc20681343fa026b3379307b81d934b55f96015d5f9302ff8e55adc4d4590fee40f348c44b4567d0c64dc50c891a2aeac621a27daf5a91a" },
                { "sq", "bbfc457fef2ca8c88538f625551d5593c43e9fdbe0264e3c074776122d45e4c6ed27cf04c2b450f34dd073bad431eef1ffaef01ece82fc176da41789d7f04ddb" },
                { "sr", "ebb7f43948acd674235ae7af4a990e1a09bc43b4476d0d8a06075b2fc17429afc8f102ca42c171d6e2fcd48a8febf6532347b0e1a1508acfc1f19b336cbc1039" },
                { "sv-SE", "7baef90d4613d59f7bdc60ce0c6e699a4a4120577d8a55294be52d6337b79d4e206d7181ad2dd81ed1ccefd03ea57ae38dcf16252f8095c210eb22b73078bc90" },
                { "szl", "c98bca8474fb4cc700b4ce4d21f9a18dbe25fa82352de1cc23e8017b8cf730555dd8ec4dd10182b710e7b789bf06356ccd188af1c129143ae7635a40eff7560b" },
                { "ta", "293edaabfba6ff3ee0ad3794db8b5873227d10e21f95a572babb3975e8e421d4afed5061e59c79cc42d035328d37adffe142e8feea572c4499053e2bdc5452e4" },
                { "te", "6218c3a80999fa8680e50870851408b6ec7c99fc3766cb687aef952709ec20da90ba9e9da306cdefa871adb5480039b3a316e1f5b1a0d44a772cb9112731b947" },
                { "tg", "99aa7e556f8d9ad7b5e4702414a180015b7889dd05173da9ca42e34104142f2c9eac69884b1b6bee9f62fcb8f503bae6d656bf372665cd0a6a00e20affd79b1e" },
                { "th", "ff85d34428578313fefaca17231b817995088e359ba2c94662822119029f57688e95315f2621096d211865e1248468d94ca8706fad59b842057ce05beade9605" },
                { "tl", "5501c5019aac9bd31784cf9f579abbe64206f983dbf2fe14faaeea138fa8288b45081794da78b8f8038a77e3ebc6c82b4424799c8492f7d97ad45a81ba4cb0da" },
                { "tr", "988e240995175e60d2fc14c42cc43723d49d0853e9604cd3b3f247f2655549bed419b000453efd1afac1af4354bf04c7a7894a4a2f63f6205125bcc25a9e1a27" },
                { "trs", "dce07a2eb8d8e6a0cfe1b3941ae267b37abb56b7806ed0c95c5ea592afe6f3207e86abe2d3f5b668d1ef7cd981c3b57a1959c9039cd8ed23f8ae048805ee98c5" },
                { "uk", "cd73119331f02e80d115e69383fc134f7394fc50962e6c0f2a8793746157609cd037286818031e92b1135d37463b63c5ff2d2daa3ff6989620041310e9b21513" },
                { "ur", "77979bdbfc55754db6e18ba2d7b1f01b9373467171a86c75d57e0e9d61fca8fbffdf522884699348e319ddf785d2e8a02e2fd5f07e9a6980822068d39242c788" },
                { "uz", "1088259bd064383a856bd90fdfb864268d176afb470d4d40e8ee6cc3e8a38c159966d5622adfdc966543434af3e081c62901945c92caa7daf993916b8c85970e" },
                { "vi", "17cfb8c67db62dea51cad8abff8c278dfa290593a83883fdc7e16c77a3d9d428e828b797505a502bef6a45e917ee3ab3ed0eda4a53a11e5d20f8f48a91d7e5cc" },
                { "xh", "f54d04c2cb00317f8f59415771ddfef30a67df5879328762d4f3af017dae1130b2455184b256ff2d63ff54df53663f5d12272a1bf5aa8f0b523d739027df6be4" },
                { "zh-CN", "acfeae1a4ebe90ea33afdfa7741f1b1b429288ca59ad3976cadd910f65cd45c725c83ef476b23cec50e00315f37c86bfc8acfd8d70cdb0e7429b3a03e664b109" },
                { "zh-TW", "7aaf45f25377a38b28cc57a3ef6f9d4e8aa2a435d22016f4f5bb476bb3c2f2af3df4646d3b2ad44b5cd0b61df977397719831be13ef6ef314c2553dd86391a3d" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5b652ca9904b7e67fb7774df01df735e6765ec4bbaa5751146a7d0cfa06f0c61f4e4d1f4533b6b9d3b0f933223a35c40df15589ee2fde7f341dda22f90616fc8" },
                { "af", "069b409b366164add6fc934fe40783ecfe0d8cd718599ae461f7f8305f75ba166b47b7befa5b89cd851c50adbacb380884d2ab611924f159ddd0dd2bbbdcfbb2" },
                { "an", "eb51e8621959b0febaff2a812189e202d00e3c216be82c780e0081e4149251cde62ea32e2d3518bf3563734ba7b16a041c9deaaad5856a0e5a493b39e7b762df" },
                { "ar", "a271ffa0f659562aed053fcacbbbc240edf157094a41f76683a2bb2c60bcac8421754a8d1603e74529f83beea85f984b218773ad03dddd81b5d12a4fd6340558" },
                { "ast", "09c2c3dc41b9da32536cbbebd1b0b6e30477a6d9aa3f98730d37a35860cc5cefa29786ef5471bb01b4967ca1e6a8bf337f4acc8b7778e2f82579de4e469e7508" },
                { "az", "1df04e428a092a6f5958af08a31839b4759bf3a67648ec8fe9ca37625c056c350036a4fdf86abd7d91cc524e089acd06b07f5cd4e11c291e71c3a7c879a386ea" },
                { "be", "efa8200ca917bd2c566a2512421754cb65e9585db9221bb896b5fe358d80f05a288ef89ee57575c251a8f893128a2427ec47f0d3ee26ff7f9252ce5c6cd17f70" },
                { "bg", "d1840ed7aa8a3914c604d3b6052861bccb5e6a10e4936cebb989dd761da63a364664c440e483c24e649e7c05369cae9b499b72d25c6591800721bdd852705fd1" },
                { "bn", "2896af026bbfdff7ae5694d389634d5996611de8fc390c9857323123bf525c8cef8ae5f2f23df9ffb0a7beccb9794b8131772b5b8e957c131ebfe25d6ed00ee2" },
                { "br", "59523ca78e1dc2eba10d4e90605d3f7b05c7c0899bf78b7a7744624716619606de2eb69fd675c81881cf39e3f6b2d84cac0fc420d71b6efe1e13af3501033702" },
                { "bs", "1e9e006c96a61b795b593aedbd4901f177f0cd7b7cde23ba97e459080fdd8233e4abcc256cc9159175826c9ac2ea433f299da871ea75b5554d73370be65b2329" },
                { "ca", "7d9da6795aa6394cb696dee13dc86cb2c78e3fa1f212da2e2e47e53ac7e33f51bf202646ae1463f7c05ccb75939758cc78ca9aecdaf35edf5affa08c5a632590" },
                { "cak", "5852d279dc454fb27959bc6d566ea43c813ebe0c3ee2310812410e57436659bffe25b5f3e062b36a6a9bd73c172d06bcba2cdb2bad7bcc6ae293ea486840807a" },
                { "cs", "3bd0953492c7cef2fdf82f3479a68befdde1476c96139ab703fd1d27453a172bf8d0af502e449dd534da24a0bd2cd7e8e8ad93de80c4df04468ab5667b7c5640" },
                { "cy", "a4174457dc7ece6e284447914cd6eedd8621bc81fab88520c6496bb6fce4cee1808ba7ef6081ee2e4155f20f0a2fad9447a21a9b6634198113a1fc56bc52336c" },
                { "da", "84e460ad662f97b45fdfb6a76de86463c14f1c9a03566499015f9b45df4d0c4085d40e6dec78f2f37702b55138853ec55c94a3133415df5dafe6e611fa862b6b" },
                { "de", "609e10dbdcbeccd8f2dea2a4928f771787056e33efb31779d0ffcbdfc35b8352ccc112b2c189c9b96f7462c507b5408cdaf15031f0fa74516d54ece64f7e5d0d" },
                { "dsb", "ba061f8ac8c8e373084a02100438b14346e9a2f283c002ce6efcbad21f08adb36bed5dc8105ab100842ffc0403c5496b01a663231fc56435a807cbcc8e07cabc" },
                { "el", "2271451a25a5ee840b5054bf31f1012bd7e155d0e2848d676e01b615d6fe584021529375909226897532a73fb14472aaec31d4a54142e819a6badd30e90b3da1" },
                { "en-CA", "0e53ca2fabe9849b0534b2593d6daf3d126c2c68f46c34ee7f05bf517994d6ccb763708a3eae1fd03534bee70f607ad7789db639a1bce844bff56b8855c48413" },
                { "en-GB", "1893bf8165f2f0c55ca49139bb0dc59cfb6f2580feefca6e32d4cae0da8d6402519e88dad3c12fc99c10209ab8dd17d802060c67af83d541a8ad254e3c649953" },
                { "en-US", "aa81e4961bcc85b5526040a47a774ad179250f26c783477bdf997b91489e00dacf8c366aa26d64582128b430c854ed03a361d62724adc0f7e543007624387ca7" },
                { "eo", "665ba4629d95a588ee6f5792c6f19ab585b590b8d15ea4707d03eb03d2f87ebd9747552abf7b7ddc7c6f7e1bf7472132d18a75cff55e574d44a2a833437872c2" },
                { "es-AR", "97eeb3071a0e34f0f57cc9288b6371bf2cf84ec143c1d138e7c3c7aa896dd3ff0496e82c8076b6cdaf5bc2cdd77a13fb6fed8f8a43d38d33bf359d8655244c7b" },
                { "es-CL", "8bff4f6e5d0969b196a4ed54d542982975a47c9d1978cf90f0e655b81a1228421b66792846c8ef7b2c5a1ba05aedcdc1bfed30941926265999cf8da579c440a2" },
                { "es-ES", "634025adb585dfc29c5e192b9ec409b397af18631a2c8d64348aeb039258bccae7a9b0b363259d90dfadc08b667bde6b8f25dbe6d7f211736e7ff98b1d5b273c" },
                { "es-MX", "b5ff309aabd2a8ae117be6550074124314a36a9d16622e55a1a7b038bcf317e4d8c297686cc087dbd72baecbf9c0fbf148a857a6f66f626707c1b3823a0835d1" },
                { "et", "32598996457c18b9a2dd61b75cfb61dcaf5ea86021f609b917360eef5554502d407fd61dcf823770ce91bf8bb417cd5a94625530b7a52f9e865bcb723bbde00b" },
                { "eu", "c15b190b73900c6a4cdbd032acc8588a4259a693961e969f0e44649fc7c22456d052cec8702a6dbc12c039506f7609e691bae6a644c2095114fd1897b61e0c17" },
                { "fa", "b2763d87531eac52c13946d4c429a6d72cbe466293ad40b6746f7e17013b167249bd266381bc45cc807818b82fa7c0641a6dff1c1db98fcbfdd7ae216702ff2f" },
                { "ff", "013709826b3c8b42af143126d5ca8389f2e78fba44b98aebf4a9c902212774bca2a9de495ce4c8d59898870a01e71149d745dabc0ea42389338646557916cbe6" },
                { "fi", "f3680f501a7a404b6ef16f44ad15a1489fa4c21f059269ac8968e17a80392f5227194bcac1dd15859dbabe0543cc313a319838b73685ef62bfd86ead2e59a3cd" },
                { "fr", "2c45294383ad17de4d0f12abbb9696bf27a0089cc400e5370afbafe8d0f2b4d8b36e52af0e1eb788ce49550888f23c7b62760c6df8194447a76da3d89e3bd920" },
                { "fur", "937e3e1dd375e01e2d48d1bf70074e7394e59814058e8c87fac3f4c871568c8d17a555b61631d8a8e5cdbffb8707a3ff12435b76d366c7616cb62176de9eae17" },
                { "fy-NL", "b6a84539259da3dec8f1a33821a55bb7fda6f486ee6cfb79eee92f91d7b1de925b663bc59c6258839ae9e0c5b83ce18ae8c773e68da2e248906bef51bf1786f2" },
                { "ga-IE", "85ef9f399c7ebd1912cd4dbaca369bb6985c9437b6438282c636761a7a676c4631283a9cbacee8240cd58b0f4924841ddfd0407a4edeaaa1bc5e97dd63629bef" },
                { "gd", "9d9682b3ecaf8ed2a945ea94534d6469e1e3fa129cf4208587ccca242302450df6109dc76c2c999f0355e54439512e067ee671c23389fec59f967e309d96f84b" },
                { "gl", "2cdd9fb68edf9cae625bdcce7498d146a447e7245750f84ede01e483d57045ad2496418b54941f516901b0cc3513c540be292dcb0bf7ae3d75e56396f62de6d2" },
                { "gn", "76adeb14358e13a7f3b0c7c84a9c1fa997c72c1973b2d764c3330932ec4e334e985cc92c6aad723e750efca4336029093bd48d19d399df38da99e271b13d9466" },
                { "gu-IN", "09878de43693e850d932f3e2c55477222569b1d5558b31a25c901eca52fec85859e0b785ea9aa6b884cac7c5b3676d74b00ca033d19079311a6f1a336cf7525a" },
                { "he", "006df7b263252df5e648437233fad7d3c2751f6d368d89bf11912ed35748acf77035c8f7e505ad980f0615f1db637c65a6e7d21b9ecfcfe4e0b8f7a0d3c053ad" },
                { "hi-IN", "ba02d41e0f4e58795d06f297243a3c0f328bf1abdfd591e6e32f7cbc6f90ad85788a200e501fabee9439e4fbd269ad0163934c7ece8b585bcbc73deabef25540" },
                { "hr", "b94881b71393c6397025c712dd5aec62fd8d98da14797c7470cff92abc66185dfef75730f639d42e1e47f44a2c1bc3cac2d54c166adbc502e82fcf382fe704ec" },
                { "hsb", "3e5db0d323968a3f178605a50a197c2f3a2a40b59242da929f7c009487d1d394381563419760128af3c231a964a92b3c602750406b35c139f2bb24c49a941df5" },
                { "hu", "0c91aa2fe0de3b6b9ece7270405cd97fd49e89a9613a357c6f09a73e476336deb165975ce9cbcb27e0c5e2d5dad9b271e432b5e6ebe3eadf263e80d575738fd0" },
                { "hy-AM", "a266ac62a007d3273300e5ef5f60a664811af851800a010cd9840c06a73fb595bcadf183eefd0fe201a09328622f35b376090a49c4007035e860fa125b1c7c3f" },
                { "ia", "a49e1530f7277e979feec10ab3a0f3e04a40a8e5aae96ee170ac941224f13b418ef5a1a3055bf790110c089a4a24b72ac309637eacc9cd7c819563108aa0ca87" },
                { "id", "af1f791cbd2c9a1a03ae5e74a10eb34b7e27520241f21e66a1a24289294a08d4914fb97f45d40b0ca393736b127dd7fe43d28b245971a1f1db449f8caf281605" },
                { "is", "a6c2f40d2a7490511fae28e032a39fe2018eb2743c2336d69a06c8fb0f7943e3f6f4b2acdaff5de6790f21f40bcf212dbd8207311137feeffd26378ee284ab2f" },
                { "it", "1fa97c58809f944c369f542039911568c8b348b943802030c941d1392feb2fbc9c4d3e11b3ea56f053aa57f050d6fa17143f0074f1bffe6e7ea3050318da4c44" },
                { "ja", "7caa08fd2de5461a5a8069efa18f5476bbfdb9b01a8cfc0d3e85800965b48a830192d80f13d30f97dfafeda2955a2e7696288415e93d98580ebc91ae5905cfb7" },
                { "ka", "4021e74a16ee4f006add998a0fea176ab1c8cd04ff991f94184073b9d0ff0ea2da5c7f015d8e6a759a79990e0a5fffcd8bb4d7863b2d6f4ac0230cdf87264bf4" },
                { "kab", "f29044dfbb41acf1cbb20ae9714b4287daad1dd525bffc883c3c9107bd8a9c9969341cfbf9d7a1fd2552282ae92774d7cba457dd6ead9741f1ac10d466228ede" },
                { "kk", "7d69ca183aa080d939d901c6913e72746d342a67d5cdc7826f357a5113bb160b5164f3221c4d2843b2371825a9d8bc5137bf89c77636c2852d145859b7610584" },
                { "km", "6a75b90e328a026a6dfdd0e630860e83aab22874bbd88500bffb1bd0dff98937e4d7934ca6e6318c4c229f50ba9663ac7feac1f34c7b54f58b4d7937ecfd10f5" },
                { "kn", "7b265ee8bd759e2458e8b3a3fb9c7c95a95be8a0801dc5a8cb7abc37671bc6e9d489ac62cde6be59ad3ccdbc8b17a6781b026b7ec7e9cac533f26ca908b00aa1" },
                { "ko", "89206aac723ddcb5aae26e926b63d5fea20ab0e22a2a1fea6fd776b5d782a06175dbb2b88b75dda13b1fc0d5a9d191f52cb264321fa9f1c0ef49f23844eb5e52" },
                { "lij", "6a426fb5f6946ac714b505b62478ef948e529ef123244ec6cebf73cd859de42cd9c60eda3483d372d7922f24cf1ba7d2e5f3cff70f7cb03f2aadb50e9d136565" },
                { "lt", "ec3194f885ad204ec1fc3f2632d4f47ba1d0d73fd382fa57f96b9b8e6174d3f92c2c65580d8f9b5e6ac444ca2a48deb44857cff1c0c87c6541937f5147ea0aaf" },
                { "lv", "a3184aa4bef2b77c50ce369f2092eaeb05b922662389111a8f373f9c5f0009891a76eb1b6f860c165adc37028518fdee9ada06d94939c007677d5c22074e8555" },
                { "mk", "14b22f19ab939af59d1b03e1c329ff5803ae91c9ba848ab3104606488391ac768cd4a60b147411b749ff2f8ff33768a6fbda77c934b9bb60a6684fa134201308" },
                { "mr", "ef3e526177980fc59f3b76ca8af102bfc45cebc11203b3e940a47127bd921b49971f14d22282254be434886c0065e778bc649d438d6556d6538357d90ceba78d" },
                { "ms", "48390732db3e036e0fc28827cbc3e3731fe9c9bd93513539a8943cbc85f28b653e4ee9bdf88deeca103365fcfffed5420e650b9d82f820a66e8f3857ea4cd0b1" },
                { "my", "9bef9a60c49748a70d172333219604f132e54ca057ddc41c1b5a47ae6f4fef84c57e0ccc1125b02f2ba1fee27106ba4fb8a7b24c973bd06eeadfecddf97f3121" },
                { "nb-NO", "ae208e6654953941ca1d9fdffa74fd50d97e4b40e46c6f9c0245b11fc675fba6acf12660695d84880e66e5f6b242c8ec27664becd5ca2866e1350edd6b168c93" },
                { "ne-NP", "ab70e3aa754f1911ab6ffdca44f6d0379ad37fae39b0bd81b91a4fae6136fc56075c4a15f0d5b338a369f4130cecbe7fdf11b2c40b327955ccea13a0f5b3517f" },
                { "nl", "12c3a2ecc7e5de1644f3accf737d4386235f095fa76f6c823243d409972cf9f70acf9f4beac5bb5bae768d56df8f4783ced57ba8e4e62326f82ba57eaf5e0327" },
                { "nn-NO", "52d7b23a8627d2fac85661b328805be5a70b238a484779de2347a30479bee1bbd1b288190c605283cf209cd44932d11ec79a420cc552c58fc6a59e84ea136b64" },
                { "oc", "190bab03ec1c24785b6fc82e32a1d6e68df3e18556458ef42a13b10d46371f1b3795e09aab6edc8f67672baf0ff8f4c4b398cab97022ee8484d54f30921fcbb5" },
                { "pa-IN", "4180acb526a6dc2dbf019701ef95eb30f16594bf83afdc34ac91410635b6ec8e294feae10c0afab0ff705c69f4e21e69bc0c58d6641a0f567db488d1dfc7ca1d" },
                { "pl", "6cb1cf22db28a721b1603c5c27f7f966bff410fe60ff725c96bac23db0120c2398a657147621bc0aff23c10c4ee8da77b3e4376219339cc40cae58bceb45ebda" },
                { "pt-BR", "cb692ba62121e6fa6e1ba53dd226e207fbfb6b0880247d4059b254424e9054df2d90b87077f53876dfe09dd6582553a333aa2c7480e54a4acbf5f365545beda0" },
                { "pt-PT", "7321622996a5ec02dadeb0c4f7a35626f2d135a01a48679b0e63dab89f110d132ae9a95df32a8f480d69a8877ea17302fd7f256f76190993e8ce270d0a541b02" },
                { "rm", "845c9c74e8f4623fd7668dfc7870cbebb78596317a9e19682a8c255e0f97e310aa6637a565ee353430a0b9deeb268d1ebc3a735e55f6aaa89c385065ee1f7bb0" },
                { "ro", "6fe8bfc6e002e77de1e49dd9d6d08ddcebe14acde280cb16c3deb55c79807548f052e2d289195dad9e7c98712fd65180f1bc0fcfd39b23dc0775e84aa0723f4b" },
                { "ru", "9e0d5a11e239c1ec7e138d6c69d779419859c9052f3645f2b7ba4f5dbf3cb9f20396af5b7609020b337cda154b7bff1761d1f5da04b7ae91c1e6671d48a38558" },
                { "sat", "d2ae08851411790cefbeef22473e54714bc22ee21a24f5164218c99515ce28a5f188ac638854c98b68c148705463dca608f9d52b5aa33d8111288983d7f75932" },
                { "sc", "6838c5442443dd62c43035582374dc615f227630c95de6a5f4b5f4bbee701d677f182fad765bf107af826c959f6431293002570c6e3345a7df4563e06d6ee2cb" },
                { "sco", "9ec6befaf6225599b2904da0fe4622db480f55359b8ee93ac616828f4f0bfa89d16856b67786e2f130e1fd7be7a87c1f1424febf04d89be03665eb289d2691fd" },
                { "si", "58065d006191fa5ce23e9340450f6306009f68de1904587d00968171a41bc895076c0bad54bc26dc0ab1d3b86e7d5e5ca25d3b743590a5188b406bf03cd5a5b6" },
                { "sk", "6542a40bffb6a908b514732813d55893907270fb33d582c69e99d21be9c38d26bb95761e444d8c033c4678d4967bbed304024c89fb37c857c471793f642fe326" },
                { "skr", "9f0e93b238a8c59c9a81bef19a2de31f0b71551a06994fc7fd12aff094ed93f606e7bf5869a2edb5fb126cf424f1424fb0435158c66442d06d59718986d13c64" },
                { "sl", "f267514ec8bf84c62beb1dad45b1be66655d94351f036fc918a4505f699003d7c40d70f5f52b61f9570ecd838147ef5c4a4fac3d458acb1dd784c87008d5d139" },
                { "son", "80747b68afe62e8c55f618a517906fa59c671df70a8bd0707c63712f51cd6284e377e3550f50aa7ed4f087c3d9ee75c381bf85f84a95bf6e0312d89866d9e98a" },
                { "sq", "eb5e1b12e4a68d89bb4bdf7813830b0e94839152b797b53d702e3b2c0b20c76a7254c96ecbf641c038de29c05e9e2f1004b22b917758c271f79a83210dc78257" },
                { "sr", "c2c05b3e891aa70f785013d1377af23e353328314676d3f99efe0490c0c325a50458d585aad1c6b99996521bfc53c20c52151becf2a9c3e70453c076bb45a908" },
                { "sv-SE", "99711f1919833b40526f1550d1ed4ccc3f795b374d4b658419b456959c1afe109b8c1207e57cb379a5fadde83a148f1594c0ec6ae06064a22286b58d1a6c9d4a" },
                { "szl", "b0cce5c186831b85388f8f11d0aada666b86c8e1a813f326c55f7416ac88d6adcdedc5a251c5015e4bb262da2d409fdeea7ca4ef66895df3134d90197ddf7ea7" },
                { "ta", "acbe5885c31e16a7b0c1d9409df6434695f5bc4d2ada431625842ea6ba87c966ec5c9d8b0ca778fcb2a341615e5b732261e61583a8b9736549bc64f9319967eb" },
                { "te", "a3c3d29fdb47fe80f1c2614f86d862dde71956064f80bbfc1e6a453684e3d0cf86a0038b0b88bf4395e5e94d8b5879a5f97c1321238bad870919c684c838cd96" },
                { "tg", "383132ad6057a33311a5848cebff0b41645b39559711672cd8735c12b15f8469b4d644b7567caf54a952f38d78f4825ace13e7b4457eee84fa304d0d040b9e36" },
                { "th", "6ed621828b53e4aa71783ad9f7c512862c7a4a5bb1dd117cb65ec4d65c1234dc19e7938ec301e196304a94f141f53a029cbf336c2358e75484efcd84fe2f66cd" },
                { "tl", "e61b01892c79173770cd58ac00ae0b4f33b5acd276dd55ec2e34f32e49fc80243694abc6244d1b309f2b3adb5989191de4e1bca862365c7ed1dedb4c312d9581" },
                { "tr", "2994d9a617a4259a2c07960a76274c0bf4a668d867cf98190c3cf1e620a1b3566b1a53422858ed90db42b86658d14664332c3a54e8b4f401bb0ee6e734096420" },
                { "trs", "2dc165c9b85d57d602d2beb12d1197c093ac19dd1e8d9b68c7d283d0d1b1b35ecced768106298c750136714436f57b609cda410d922afe32f89fd58e733cbf09" },
                { "uk", "5377cf3a446a8572b3d580a1f11ceda396542b265d813c07f142ff478fce5c080e9a9802e2065e66834ed2ca6cdb45332cf967732d733d0591d31692b5800f78" },
                { "ur", "e42a90ae5a0d79f05e64e7ad782c40213773187988973a35cfa787a6f3f12f8c8eb7309dd28517d7a6e22a1b71cb94465b6866ee533451df6b0303383a1f1c79" },
                { "uz", "d53ddd14ee0043c750377563478d41f99aaa7c55eac17bade739caba5c045f1bb144e54a2e34a6c04d9f61f90c37301ed4e9947b3119e2a98548e4db61be53c6" },
                { "vi", "31fbd013ca8a5abd670eda3ae946c817fd5550d3693c6e290ca4a05d231152475c83e3d8496a049cfb520712491e22b070c923bef443697bbd4240c8254599c1" },
                { "xh", "06de5b031ce37a50d7345cc8eca5d80b3af2ea165e99c1d760fe7bbb1ae4d64fb216764ed3aee6076a2e9a0518ab84176b98c6de2701fbeac321361d625e1c40" },
                { "zh-CN", "4b81ddf5d10b63db3af659c92cab485774ea4c2ec98ac0ffa0e2b143cf23775d02c751c0d7d410995cc2a40fc0ba646030a0bf40aa53fbf1df3a55f7779266f6" },
                { "zh-TW", "4bf79f62338882829e74556f43adfaeba84cb6e06965a377ba1fb46148dfe5b99c44808c7a37c622ca33707745229b6682eff41ee32b814cc08916b3645028a2" }
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    cs32 = new SortedDictionary<string, string>();
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
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
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

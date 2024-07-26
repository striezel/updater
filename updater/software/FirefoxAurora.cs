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
        private const string currentVersion = "129.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/129.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0862db60e2b1b3e734d03204b23508ac3d258686a8b1b564e06e1e007a5f2b8e451aa86f70867a8bb2d1dc1eee5472d2129fc291c96114ec1b3850474dd352f8" },
                { "af", "ef209fe4a1cb39f22078cd5bda80ae66e394cb957906f627a936a0f05b1fb76daea78a579659ae7c34a1efa7dc8ab336999a1bfb54ffd39eb008741f64fcba81" },
                { "an", "e7a335b2927f9fe685e3f31fcd4032ffe255d98d19f570339872b4c87917b8cd2718aedce78623a71332e07b69ed3318f3e31ed424960326f78aa4f581c7bdc9" },
                { "ar", "262afc4baebca834a32d3168b1d96353081fdcfa2055ed7c82dec39ef3f7f00db8aab7232917d2cbb9bc6da4da7826af6f6889dbe037bd9a2c96d38d782af76a" },
                { "ast", "3fcede0519a4fb9eb306a66b8fb6477232647948f1def51cad137846a80b61c23ec2ad31b3996388d36e1afb1f9bc1bbdcabf14b344de3484fe816bc2241cfb3" },
                { "az", "75cffb21b2eabd25a1a209b1a204d753464f941daa8ea7bd1afcc28a43fd89084a33fad742a0961c6d66cf2f9899e730ce4edfe7f10ea6fdb9bd6d6f92213ec4" },
                { "be", "09d42e6bfa4f5637d91e863e29d9b370d5f3b43c3c51787c9fcd648bf0bb0100a2c7ca44706542956ce2ea7b157dac8be26e5084b03ae8158f382af4baf6be51" },
                { "bg", "96c08e2e0e149bbdef11307a8d2c699f90a5c7712303ddc6e5dbc30b058602ba466522fd2be6c385de4b6023ff2df82c05f46a9b6b3a8486f38a542a927e2e9b" },
                { "bn", "1d6fd1b652b4bf3bfe94831cf19141ef99f836f595c6635966803e5d67eb2034c67702cfc17de7f76aaa2abae1447e592a89e7588c14869c6eda61a3daf62d6f" },
                { "br", "112d9664629220e41da0721eb806f4589e5a96d82e2fbef2e3fafefe7860614a7c6bb9d69fde8b0fa381723ee10267e50d8af059b775372b4adbb5147390123f" },
                { "bs", "0486bf6cbde6ed347d3476fe91fa93f89131b60eebb6cab210f504495e3440b464d3063c0231817a0a5153cea40bb7291cda3043c2cf1434b880acf6ccb51aec" },
                { "ca", "5bd285b14c5668a70d8528fc63b18bd0d1d8f251b3a89ad379f1ef03cd2fc6beea808a1ef1bfb9150315e3d2b979e1ef977622fdc4df1da59f30fbc9e4c9e89a" },
                { "cak", "e27770c0ca842d5b7e37f5e0d255518a4b50d216bbe4cb17da75a4dc932588c1d60d0f185b88138de4e5f26f27ad4620b98c506bded3b03df546178eaf729dd8" },
                { "cs", "4c11412ad4775aa712cc0464e755798acde7a757ebfe69db1649df8b4200ebcad7a7d0fe0a17eb60d097ffae151aa2b9e3b0f4693b09408d7a7575dc3424b9de" },
                { "cy", "74e40cc2250e2433e57246a4b2ea17c48ffefa99758a2df2cd0c467d2719afab44f0ff12e67b63851282c627c536f57f69e8b1099218010bd5e800185bb8529b" },
                { "da", "4c3dc433144f85fac9d51b95725e18c955a4c42ed9a866e74397a5d21851c337316a4a8c32a4328068592b56968b2107e0d4a3c30f768d2cd5bd12ac8e652166" },
                { "de", "21709f9447c43f39e53a2175d7ff35feb4b5b4621589323a6378af8e37dbac21e5234af856b97f846e37c4cf833c5e9f3f873585394d9a39fd1b0a3dc0d2e70a" },
                { "dsb", "0f6aa8ac1ef51286aafc364c3b7593db64f9c23d2b5df1a02d4ce98a7e75877162012de1a7520ea07f5d88dc2d5d7879399dc6f2d991058059ebe17487981094" },
                { "el", "3462333371094f4a418a157c9f2b319517524b1fa0ebb6434a883c0b98c15bd67a0b4988596cbfaf5487b731071c6c54d071ce3a0f6b7e90ae4c65e27c48d470" },
                { "en-CA", "66c94b6cf1ecd112132ad4e2492ddeeab4355a81f7930d5591ac527594f9f71fc536f597286c83d9998ea19beb4591bc1b6bba35ae7163e4ed392f0dfb663d1a" },
                { "en-GB", "9379078bb92c69285e0210647c2f4ba251b1576f8d788979ce99095574f49a3d1ef0a15dd40986f61f8fd181461fd97c1bf91827003bd5366a48bee21e44eb4f" },
                { "en-US", "a76f4c315c3eb5182bc4bc2d245513b342ab07fd323288bb5e5646c4e0de75b0337e7a513e59d31865406e36f1bad40574811cbb56cec37103e3ab300eb83ad3" },
                { "eo", "e271c38e625324a75e4dc0aebef581c42b560de281ecfa63f6157402f4bd3949c6db21cc79d9cf8c2af5e466b5cbfcbf202800f708bf47197a9ce17f62e1558e" },
                { "es-AR", "43205eacc68cc83e4cc14ce5a18dd731f4ecadf86f466b8334b999af6bef4e8c3af152aa51139c1952edbecacbe2988849c5e3306d11de7203882be3c37a70ae" },
                { "es-CL", "faef99a890beebba5742acdb61882050d82a4709655fc9327825eff555a3be41b2661ec7f81f484aeb0b03279fcbd0ed9f8d712e2a45d37a2e8e108089f7192d" },
                { "es-ES", "271f0e100250fd262b98f5160d57c3a7de383436e27245daad174787d61b46fc8c03b6520125481c2f3b31daaa8a6c997bc5c774df1264ae9170a2c85aa938a8" },
                { "es-MX", "f35d2f5ef820db33b5c352da0d01ceeeace68909eb6f7fdc6ebb574f62679a647c7da87538bdb0e69b843cdf0e5132adcf542337623a37c9c0692d1c8cdc059e" },
                { "et", "cdebae96e0c4ccb4da72925a6f706bdf2692c681de96ed7a1364fbbf5d1a770bcf0a0ab7cfb3a1dc84cdac07f21258ea673212b3f4cef2de9bc9450e3e8c1dab" },
                { "eu", "70ff663ab11d5dc278ffccefdca68a2fb124901ac64de55fa800cb1298403dce870d9925084f4688ce81e3e36d31d33d35ea6b9e04e8be1882bd56cb7a1a9c3a" },
                { "fa", "eeee91904964ab4e50cdf5184bf0e7c4e519fdc094c1345261a7667887a912d6acd7afe1e4774e5bcb7e50919f8a0fa314377b1d05b775a193af0f622a71a4a2" },
                { "ff", "7e028e8aa702c19c4dda056062b4bdb4e3b7bd7a478750ea84711e5f0da2409471b0a42b8e32744bc38b2d72132ca073be23804c7adea09d1963d0619cf4e4dd" },
                { "fi", "4e6c19de8b8f5e9fa6eb51e4e08f2b58c0d8b21f0cef25af3fd32e5908771b0247da01a727faf7e33b89abbf3acd34e8d3732e6a9361b6535edd816dddf6bd55" },
                { "fr", "c080d331fb4649ba74c4e70baad27e4fd16139c4fee02c2663d155c8b701c655a523a6f12d8161c6ad55da073eefb63bc93235835417a21732eb59fb2443584c" },
                { "fur", "b1adea5c5e435f2d6e3e703da667c1fbc6eb0467b7f7747f497c1dc231f4c4b066bcb6f0b418215f8c57ad344d6f66d1e275dcf184fdcc69e3efa57074f4b50d" },
                { "fy-NL", "26a569e2c36578e46d821754b9687f7ea60e62e3b5496d15a56eca6b3754457ca314480b95f50cb2ee9334cd96fdafb102bd9f0b3969f69e2b4709d31c673eac" },
                { "ga-IE", "4671b575ae688e05b52e03e11d0b6de5f43edead590fedfcb876243d92fda63964e6a4accdede63ad5fedd1c5551215723f5ea60a2e2e6f29b49e48902b01610" },
                { "gd", "5d40e5933ba8a63c4683ad438a5d9af2e191f01a387462c52b2db3ba27f54f9d7f5d72e1660dd8ba4a9b5d3fea9801178f6f79151639e5dbf46a622ec89858ce" },
                { "gl", "7d597062e4f43bd64374b196b516d820a6cc17e34a39933aa1e6c1c4112d55b0f02726130390abbef027450c008cefce6e91e912a399c5bd08d8f7784cc65e8e" },
                { "gn", "a9ac9459c526a7c885fadecfcaf41c526e2bb167730fc0569e5cf2f7632894bd3c89e0c4bf587b4fb6b7bf55a8a4b175498f0100c0ccd7aa4a87b42cb5ea50aa" },
                { "gu-IN", "076c867f1307e63ebc51634ef9896532095a92db4d90e953b13de12f7feda05ed9fa1d60486fe1f5cef87088097c43655f16c09378d4f6ed36e13f0a4d7d2c5e" },
                { "he", "7714ebdf97d487cfc968ea4b9ec637834001734a7e71deadf7c94863c304a82efb49e87922e243f63ae8c690b1a251420e6509496ac486ce1b5f933a191765a9" },
                { "hi-IN", "113f9ebf60a9fe0eb85f7fc25a7a337bfd73312744bdd0568e04153d74fcbab0d0d70a88769dfb44063adfa6d5576a2315a20c40891ec769b493c1635a31b270" },
                { "hr", "1c5f9f4b5f4798db7ae3cb969efd2c0e939bdb8cfac4e871bdb16544fe788786f5ad577dff245667297cdfcba69ae8be0be64c8c2e4dee2b00783ec7e21934b2" },
                { "hsb", "7e90824ded17eef119580d05129addbc3d880325849b2f492b17a91d218f2acdd2a6c539392eeddd01765fa9618dc68f11aa478c10e9211a44e6c71c556da596" },
                { "hu", "a6134d32e2bcfc5ff7b268d7a77c6ef9aeedeceadad3107dc88afb13e7311a724e74259f30b697f3da996e7e481318237670aabb6f52eb8d33441d94dced8d4a" },
                { "hy-AM", "45750d88db18540cf0bae42c4fdb0d98d87786404d4cc610bfa739e53c814b1bbf7689ab624396d398c08e64624785d8453a592451e853e6f221e107eccc17aa" },
                { "ia", "9bc3b1850231e69c4977e9bbc3fd50c8ea88330bb2ebc837ff0bde7e783f41a433f1e4bde7dcdc612d8e33e31fdbb4502e5f382acc8275d3baac243f7d6e5e55" },
                { "id", "0aadc63eaf1ecee4a832b504139926afde9999e7f231b2668ea9950aa07bc8f415c4b2d75ca2e9437a4bdaacb2ed4feb03a203ce9b5d3a3fb8e7dba1b4e2f908" },
                { "is", "f927aed5809fe5eabba1e5c3df69b9083b423265a4f6cf1a65a5dc78f959c58a8080c622495c8243c625ca66b6a465844fdb1727e019908df4d0d1adf5d8ec79" },
                { "it", "fec0249c23a7021170b2f11ce26bd3c77d3a1f7c2ce326d05f9290742207fb8f07498ec04dd101d6a469f8ba34e6e52643774e8255f1a9dbf77029c58cc19c39" },
                { "ja", "3422dabd5ba459a51a64203d9558e62e1c7eb7a3250e6a4f1fa810b6b7743cb1489d91dd39ba98890c3ada820d48b55a185659fdc6691e1c9a1361eba35ccfcd" },
                { "ka", "44c46ec1485a75028bcddf724aec9ac290b42704909c25abbb8fd489b8bdc7a737f3659b1af884ee7c43af4ae89dfc628bff8dbfad648ed81a37a2d3d280f7c8" },
                { "kab", "76d1e798b28cb07a9019f25efe420f0ea7a7ea2769ec8d46ea2539360496da0b12a66c89b7c0476d464d12ea21a116573d641f00ed5c0a19a21ce0098d762b79" },
                { "kk", "39e89feff0687b7f64164be1bd1722949cdcd7d19433de8c4c1c8b924b1574865fe6fec3b489b05e8b510546ff64b123252a46081594c6587cfbe93547b34c45" },
                { "km", "49316d5b5e4a32b244c2f46c845bbb9a56aebdd5b5a0ce212fc81d753dfe0b69075dd68b75d42d2cd8a5388d7f85914971e657458be2557ffc3accb3a669e148" },
                { "kn", "abbfeb51a9d577832a0f839a5923255bf4bc75673f9dae767b5b7b68d0edaba24f942417aceeef2401bf5d7e0e71fe8eb0c68e9bec7f8fed4e8c0e3658358f53" },
                { "ko", "d33d6154b4783a30ef1981e7fc90c380c41f22b1bce1a73f04487aaa0d8f22692c3b796392349f89872e750de6b59384468c25de369fd40bb80d282a0747178a" },
                { "lij", "378c3b05bdd8e7aaca9144bd57a97aa2ada925813c33e7f634aec4c5d58bc24a66e1676cc46447269f12a96be25ae59817b3a0cc1e0dcaa34229ee9652e9243b" },
                { "lt", "d0c72a3ac6c3d7035e68c77637e5661cafaecea2a7e72b9e0eef5f5e7a42a57bc5129636e6df4f819a5a99256e2b8f361e9f94c9fd37135237754c31d2e1fec0" },
                { "lv", "9f33a0f3e13462fce22908fdddfff34f963de0edfecb816fd75b621d10cbbd13859805f830eecccafbed04961784cc4585c7fda2263646bd9cdcc5f47c7b3a3e" },
                { "mk", "0a0551afdf3155d62634c7c3b65de792e8a0cb0651c5c430c2490f1348d9d88e2964ad8b049f093f9396cd1aebeb4b10e7fe94d723ba94ff5e6f27f4f4555e46" },
                { "mr", "4ab783fb5c540e51676088b4e560580a2a7b20ef3a789c5abff5be73021fc671dfab9a0218b6d3f8373458e7cd9840aa7c3849d440f732e437796abbdb12ae85" },
                { "ms", "c40a049b2e44853f600451f63de8e8f0cda88c199dd1819fb44525c804fb10897a482e6920310bef69092088be65c2b2bbbfac812bc02d371710d323dc3b1698" },
                { "my", "2920bfc1e8cd9f3b6336dfa976b56540fd8a62568294f2169707544bca807e8edf1de2fa1b7bed6e3afe8f4594c7f70bace53a0eff73e4295b105ac41f6bd1ba" },
                { "nb-NO", "4673e7f651ccc3def00bb8599e06cc374233d2e523d2ee4adc85c88f4f15a475b3968e135d24cbefe2d1a0c4820431c5058717cf26ecf900edb060cf21d0afb5" },
                { "ne-NP", "3c1ffe24793736a827d2ce153047c1d01c61e18cf48fac2faff55b6ad5e27411572784d1aa5ae2510410901366d071b3cdf8278e069cba6fad0ee2792fd45c09" },
                { "nl", "c19f1dbfd4013ff03be277d8144f84c769b5cc1679e9c0c7b61537249a8f26b06678d23da82a3ffbac4f3fb99f0467b8865d8a822107773f651000504226bd03" },
                { "nn-NO", "c9b7234b1198f5c781654590b1e7c70ec54ce682f71cfdd23bf040a70116d252468b8df3d5a64180f8ab5c0c60e518063fe9e31cc08b15bfc94a239f95359a51" },
                { "oc", "ef5c6e27077f1908017e3a5aee5d99b24a51a5126c2da5bcb1e5778aeaf6a0ef01b1889867ba4bbbbd83beabb91d8ce15f4bd6bcf93cbb4b7f5e6b20083e54dc" },
                { "pa-IN", "bcd7c285668c3539be104160178054e114a5431b40fa3f7683904be78e6cf7eeb9890415c8f21af41f7cbbc15e02fb16802a665659334d4980d83341e454864d" },
                { "pl", "d8ae3ac31a44109001b4f6605acd70a36f79066b00e04ddcd27a919ddc7dfa93cf84f5c0863a20ec368f095b5fd011d93afb66525c13de1a07f71d2872caba82" },
                { "pt-BR", "5750101da4a9336f3ccdf9fe78f4b103b2d28fb80ec194734b0a3c2ce37cbb0609d14094a8733ca65f871427229e91b7044373bf36c9848f8642db28d23a4c54" },
                { "pt-PT", "b21f6e0cb755864edf11e25e5905a025f6209ec5ddce2f728b3a92e3363a7d4db1e40334644cc8571e8efddf0744212d016bbd6e96bedf40d61d19904e590171" },
                { "rm", "b78f165351122ecadde90f84b9d7140290906de59d8f90cb9fcaacc8a0a9cc1d244b5f47c5cb646a09722854f7258b243bc85b3f927210e52cb101e6a5b97f83" },
                { "ro", "0f1e9705d37879d6f532ecd8df67dec83d37ad87ec360d9c0fc637d29b2d62eea13cbbfeee1c1ab06f495590cf7be12c638a9bc3106ec688525a3b679a7878e3" },
                { "ru", "3f23c42e683c4616af59cefaa45d17a3e3a0394a069f3f10cec52a8d86d25d6bb37a67697bdc5b3717ddf4ec33540743ca5f3282ee3c7c18665ff7dc6c6851a3" },
                { "sat", "87557cdbfb690accc3d1af3da1eaabe9bb1048cf78ebe833a1f59c1d43b8654095984813297ba531129ea94786244136918549e8107023074d79cd7cb76de64d" },
                { "sc", "26a65e8a252f8b1421d243bdb08dec69262f63911d73fc9bca8c7942c7e5a1a3347eb5ad08e3aa069caf4767af9edb1bb8bb2978372e4eb686d6891b91e424f9" },
                { "sco", "c40a33bc602996f54a6206b4b767844ebc4cff45e812042e8301a77854a0a8a9dcb5bf9df943eef99ddb597a3d92a288cfa2e8e7d7cf4270de33f34ab34386ed" },
                { "si", "eff55e11b61f0f8d63ee9fb02043216f939349d13af24ba3287f683896dbd66dace24ca91c9cb60dacf03e5047330644e685414eb4f5b4c70164abb77c3a4fce" },
                { "sk", "8cab1420a3a7d4cc6f00083dcc3c73782909d683ab6d1f6cd1e9c5a151d24750dbfe2448a57580d6b5fd9fc7b5c5ca8777a140a984a326e739d81cb18102ace7" },
                { "skr", "fe3520d500128a92dd70ec43c756bc273fd837ec77b7c5ae71e5784a8160387cd910a6494edafaabe3fa51b81f06672abe8d2ff84b0435a826004cc265677749" },
                { "sl", "e4f5137ab81ce72f5c7b6b3307ae1ce35c90e4bfb420aa0cc92a931491605a9c5e88090a8a792d838efb55e03353a752d01cd9f665e21c382c3ee299feea6634" },
                { "son", "3a5807796d30a9d151b4a3c7dec9060714526e04ba5cdca467a7c4d41c4dc4d6c9c00086da899b58c324cbae7e1bacb3d0a6da437c54e776a1d51b159ecc5281" },
                { "sq", "46a8ae13b4e3ba5f7e44b5116b5fde38f14bf370b46312464a2ed005152f558a9a1b2dbf6fc47582c9fd750f096fadd04fdd3289182f7bcfc5880c9ef8b4bd88" },
                { "sr", "79e8957306340b1d3e3073ef1df50286362d9041b9fb33856f682192c0ff90a88c7cc2d6f7517e8c442fe3bdcc2d512112864ba03670e163e86d50c468294d5a" },
                { "sv-SE", "542cb7c87a6745eed1a3cce19916873bafbaee05fa77410fcb255cf206e4f818308689bc4ab3d8dde823f2a2399d4efed134eeaa21b2b3d09b091fb8de2ab85b" },
                { "szl", "677ba5458cea2c2fcb12071f94c3f7b556341cd97aee9f1ec255a8c03eef6443da1e95166d9123ab3a8494fa1724bb4d083f5f2fd82fc80e2942a9f63abb2f24" },
                { "ta", "d501ed11972ed20c60c4fcfa81c458d13c2efe5a7672830ac1b653158562109898da80abcaaea4d9127f96bb892a265f0bd183ed5fb7f00d95d1e643c822bebc" },
                { "te", "a33f2ec95690e572267046c61fea4d638165da24b56731b1d5a69d8e9f699fa5c7f167613f3a0fbbb402731d3056d2389a13fc53bf36d80d19be21abf283ccde" },
                { "tg", "90e9bc443746aac3e7604dae2795104035a74372651d2db151955c91f582bda2afb4a7c237e1b8585af3eac3904c0260b978cb86c7ba210b54cfac02294755f9" },
                { "th", "135fec5747f7ea9b5c829a28598bda3b7788637545a9afc1d449cdb4c8cae20423aba0a43a94fea5bf2b86ca23a645f723758793ea4d88f9f4d1978c424ddb83" },
                { "tl", "98ffee9302e058b2dad07a2c86acb8db4f1e4b105880ee5387ea40fcde0f959923381abbb1ba19872a7e3fab908862ffa209ac58eea360b7a32d839b644b572b" },
                { "tr", "c4b706c21e60bbb47bc5ea59c5da54354a5315e0ed5d81a78e7fb76bc9ed861040822e17a6b7290bbfc54917e96e36025f97fdf1a15a8ba2110489c54553ed80" },
                { "trs", "6a81ddf185b26f1584c923cb8c48b749650cd7181dffbdfc0d417fd85898ff953af845ca0afd3c8d2ea977b9ad21b250a48f227e3c3ab80297a9724d7be8c19b" },
                { "uk", "92a1a17a3c98b14b4e3fe364d983de5bed049784d2bdabbd5a3b603bf9efa6fd6bdedd996e86dd30421aba8abdea7df6860796cee39512fb9acbfe7d27349e00" },
                { "ur", "7fcfd11678b6f262388c8583c25deb9645999ac88601462d1a48819238b21bec8580a7e152d0ca1a47895d710bbbc9a2524f940d64da103e5278f5b34ebed269" },
                { "uz", "282ec98779f820cccc514b778e445ed48c1451de8632874aab4ee3d0a100b76106b199d3720a319863cd835542650315cf26077900622efa72d207cc8ba30a62" },
                { "vi", "0e62ed342d7df6141d9f505b588f4572156cce5b3cf24ffc5ebca9fff369c05e8dcc9065224a69219aba809a43aea5bcf53f54db38e43f745cf433b02b301da5" },
                { "xh", "1297f6a5345f0eac68743cd43e831fd9f63344b6af7b22303c8db2cab2b8656a132a2d6e558042327b4c9b10cdac21487646853c8bc4ca278247cb249ac0d619" },
                { "zh-CN", "40545297f5accf66641ca54be85668664fb3c08d7f3f143df6521fee55326e1591c3639465256c0706a5bd49fdf71cedd08cccf4212ec89d1a39d0f34686a294" },
                { "zh-TW", "176281472d2e40278e9b8dd28867e872df152c1d5bd4c67423b111c7c8b360f71467910dd611953037f6a579d12fd581bfe9a9723073b9b4f606cdabe336e168" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/129.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ad7dc4ef2c3de69d4e5fa7b13047379eca5e9dba44f9fa2fc093b50b90d91b6a3a81df17fc65788efdd654afb12f4449b50d019c277993b4a390ed1cab4aa388" },
                { "af", "6e943708c4789ebc7cb8921c4d023e4c8fd4b44511fc8f0bfd7fb0d7fd7ffd79b67c79528727d970fb64ec7f98fe90ce1e08a921ba394d0b42ddff80ce56f4c5" },
                { "an", "0a49eba7883d16a0fbcc3d5b7adc6ebf5eba5ff7448969a472b316499a126e9923b39de1071c4b7e18a4676ad139cfa3e1b06e4fd74a6520ca41e32229d6bd46" },
                { "ar", "b047b8401b5e47c240b70161e99e0581462f48986700baf20be7d528488f482de43c2f578651ee890f5f350f99c3c506e17106dd602ef63096723ab38d926560" },
                { "ast", "ffc3cb218742e0a90ce9cd297d7411a0d162223e355112c22d89fc1b8ae456ba32068fd501dda24da06ef2c12a3f7b389c0b3441775047f061bb7c06df9314bc" },
                { "az", "55e3c93006e8efd7774210c23b8185d7978fe64a994a3881e1c023cb5594b014695eb9e64f17d4c79a7887c49ba33546624680ec38b755aa9946b1ab160cf1eb" },
                { "be", "5fe510765dd21b596f0b5dd3da8effaba5b3f7ebc469f3be9d5251e04823fe0f093cc9407d0a0bc10ce87cbd8dd372fedcfc7c0cee4d623854bc098ab19f51a9" },
                { "bg", "5d70e2bb1f2b7c33a5c0f88567de4d4c762652fd4612433d416f132063e33476aea7712e031c4844c13ae6a3e012de213f54cb0134094ee2bd0f718a03afd7ca" },
                { "bn", "6c765113bafa71b3d158dc9bb73ee3a26c6d8798877f79383d0167fb096fd0f475438bf05054f9d48c8efada4c94c7d3770ee7f44609814ac6bdd60cbf856112" },
                { "br", "e3c4eb35e2c2d1a415f1ca7a0a5b76f73d35ea70dea29f7fddeadfaa04458846a36d856f34d4515edc1b925595c9024a8f2d61f933dd7efcbaab7a3286327ae6" },
                { "bs", "0026fc0f38fa131e02b1c9fb81b52414f03aa837e48b58ecc5d1397761336a60cc055c7567dda0c2e551f717c9e7d7b69e380639d2d97addf458ecb7a2a75db5" },
                { "ca", "74942bad45c4ff9f63512fe71f9079ec2f134973a863f741801dac12dff5251ed9454fe2ee83616488dfc1a28d80b351fbbdad7cc6224f37471570f85baf40e8" },
                { "cak", "4c0c2f07bb80091ccc4e95e81b5fc2bb0643e8c910c81a512b4231025695d9bd25dae99b0c31611d642d1dad3ec657575a7f4552665c234a07a368a1fa6922d3" },
                { "cs", "1ed9b453d02110fc73abac6a21f106e6925cfaecedf7d79f3e910d1795e267ab47ab75dcb639486224e891b4312384bb0e8e36401118e91c7a83c7f11944ce22" },
                { "cy", "561f8634c07e5145224229b63229a390ec022bd14ad6756a16575c86641d1fae2541350f4a9d999f853083ab2f00acab410dff69dc1f5b92d77bdb998ff01eb9" },
                { "da", "6a5a543ef94ea92d0f4891832f840e32943beae85368639f573a957dd846be38d173a890557e94cdf9354936f374046c06681c540abab4a0f0f76534ef5d75c6" },
                { "de", "5fb0a2014bbcc5ddd53d0e6bc8a36add3df1d3fe75fa2157f46b050742e3e9ef47edd1800a1fa7f946d0e3bbded7f0fc11c0c8bba8fb2720bef664a1223e515d" },
                { "dsb", "1837c7fc56403253b04864bfe7f5eda7395c5277779fcfb646660bf23d625af958c420a10719f0040f5d5f10a3ba9dce11c657a2c182190b87457f6dcd804f93" },
                { "el", "d6a18182aa75596be0f4eea5b90e2103ef6f12adb36cb0ddded207e8af5e63ba6111bdfb0bc3a6821a96be47dc924cc97a7f9bb5cc04a9f3a7afc25617ca078a" },
                { "en-CA", "ad7d15fbfcf64e9a9f74243ff1d1ce313400db3d2cd0b55f6e5567542ab434ccc0ecd75948140c439a24ed23588c001fba60d2c0238c573fdeee9de937821570" },
                { "en-GB", "0196771e5aebc89e6562acfefe22877797069dcf8f21ddb76ce2b48d28bfe4e2a4817484ca66bca1b58c6ecd8d3766ad4b960d5ccb5aacfb09e9271f627c14f2" },
                { "en-US", "e5bfe3f4503fabde51fddc14b0e1e15bd595c9c48c014c1c3712f6e60974cc90a5f50d5c10c473b863cf361c4fa83322ec91d11f4113521ca0faff1f5cc8f2af" },
                { "eo", "faaa90acbddf97625bebe21f9d26371812ac1c5745abe19f5fbba0aa952bd0fe6bef21d4c321087dbd0204d2ad705f8fec2bb88abd7f67d5f2fde25706796bc0" },
                { "es-AR", "470b973e95b55b0493ab104fc4089c6aa366f79670699a136722ccce681f48967152ef85a045a72d230fe85fd9ac21dfa06786f42c39e2b85202d79b64e828ea" },
                { "es-CL", "715ca72631e8635bc87061327c4c00b1481885bad3c9e2711f798f768e2a1b50adcc156c758a6758d2566bcc217f03bfea99d816c8e5c7d781b2e2c4d8104add" },
                { "es-ES", "f775884611028750715cfe2803cc698dc320d50a791012d6d1ee67c45a2cf7cefef4ddcc84e8460707947b6516deee0c02d16bda037078ad5243db9065515739" },
                { "es-MX", "2d7fbcdaf76d71e727b1753b8cc106c4369044f9d7a7387bd989ae691ad3907b0251e3cba09505b31505f3ea182f169fcfa525c77c661697ba591d030861ae1c" },
                { "et", "7218c5f36f1d8f7c0b4038d3166c8d199382d9d1c675c8ebfe5fdb09d3d691a2e69bbd33b12358d1655c22ed249e7b2debbf4fbca9b30bbdd0a40ffb3df38013" },
                { "eu", "83d27a54984c2e7b298980b0736727ecc4f6ad2b9c0eac6c02b0750af58cfc084f7d8f430cdd860ccbed443bd2a3f235f0d55f50b7e922ad3ea932524c955688" },
                { "fa", "043acc524be8247b4fcf082f30bbb9bdceaa54f5da6189bd19b41cfe121f72b6ffbd231e1057ddb299fc074af8c8b2dde90bbca07b0de62c9f0ac58598dfc50a" },
                { "ff", "956f3c3da535bd1edf8e7b6bcfd454fc85b49d396cf84462651245b4290c2a104e15a306f921b91a969ec41c9ac0f59805686caa5e03d3694ed4cdcd11be5a30" },
                { "fi", "b9524015ad58bb606b5dc36df73af941ad06e0242353f6554d46ff7d5824adc33b4b3e3ab3d025ec754b24a860424aaaf8b2d3138d9689e82c3fc4908eb7816b" },
                { "fr", "9b3e9a08a132c723b3f75f7405a0fadc200c0eab23a7bee012b311612274fae044645f0c63a11d784b8388cfb864c5ee96a8cfaf47aad1f52bb384ac910c42d3" },
                { "fur", "452bdbb4f72dfdf5100299d1ea3b9ff104dcb3a04572aa304c050c4360e01cec7fd3285bae8eb7fb4438072f355f1e41b4fbbcfc5f40a6c04facb4c3310f653c" },
                { "fy-NL", "9b5fdf309550626c575d47ae95cbdf612a07fe2e3194a5bf69b2d4c418f3d10fa864f423af34e7b57c25cdcbb62df8fe0a1e8b9329ec9c3f65b004005cbeb829" },
                { "ga-IE", "8fa50784cada1be7b94a6cea4a4501d5d107436968f4a01fe2089b1df8e31cc01cb46b97453bae865e58d9f91ce9eb2c42d16b5560d8d012db56b0af262cb6b6" },
                { "gd", "a28148f1aa5c745a1788b9083935edaa953bb68305c7bd551fd19cecb6584928a700d5dc3389a82997eaccd2d37b425a809597fa1ba316e0d5c3528c4558e43a" },
                { "gl", "aa286f4a620998facc3e052e89f9c6a299e4366186a12ed5897ec7888280a2dbd2f392cdd6742a0b3b5450020ce4470eed52ac8a751b694854f1ce7a1e9cd0b6" },
                { "gn", "1a8a6613b81db07bc3d528b8f2bb8bcdd6bd61a525a1e3f7aaddb502d5f68fd05c8dbf9cc23a6296923b710fc84be7ae034f4419953bf833c631b9a88605203d" },
                { "gu-IN", "0b84c3e8a4c2ae78b18ca621aee7c26da71d441b35b85c450832fb859cb9a84cfbd151ec1f35cf19823611456756edd75be1542cb708baf8741b3b3fd959d5b5" },
                { "he", "498c9c7e0066d54dc397858daff361bc2ed5fcd7c4435d68916e9c7dd4521b2c53e8bcb396de92436d902f5ecd9155d24a3f4e7bb77eb7e5c36fac30690dde20" },
                { "hi-IN", "9f737ec9e14f6d3b6c8fa423247c6af4592e3d5ad83c9a95fd9cfebf6c6a05980fa43ca894ea175aada8138eb9ed31b64d2a9463b019074b58001f0fdf9ae1f5" },
                { "hr", "3e77d49b6a3451473fd97929f5d6b394809e0052b779c78d496bf23bf15b2dfb3e3fd51e29d8e658518bd9c1d44826ee9618b8d2a5b539c763a424644550c1e5" },
                { "hsb", "a9e3d37f5014628382e4a39fcb9abf568c24964d7c0e30e5b751d50278f01c7a9b1e4253a75862b92279a82380da784fed888ea901c0bcf8a9b6abe7adbe187d" },
                { "hu", "704aa3cbbe01d0e0103ae1b03096944811058b5aec87a08b553e74a57260971615fcf1128cb8908162d30872ffdb28b1d745b6c71e26a96c4a50c132d5036c17" },
                { "hy-AM", "697ca3dccf349ec34351ae7449b01cc36dd1d9648ea0a52cd1112a3077d6021c27d1dbbdefb01da017135c0e081d705c9cadfcf849e129fb6579815b45007877" },
                { "ia", "090820843742f26e67fcc743c07a4d6e7a6eaf8ac659cec679a5a676d8d54efeb136208f21e3e69c6c27d10140a0820187f61f84ded2f7c0e666d06371ca0d93" },
                { "id", "d050f00a8e9a47b27705a292d30cb7366a3f14ebf13d2cd250586afdf6a9ef8ae5af647c1d3914c30d812878cb220949a65992f7a901cf6e91a7817c4104517f" },
                { "is", "3d07993cf4df921ee4c12f79ebb48509b8bf52d06f0509b9375bf95436c4835faa2bd89f819416aabe8ea83f07544e5aae2c719be867503ce7546473051940b1" },
                { "it", "8068d5da6e16ccad69b6ce960bd1e46084efd063b5a7e1c0a234f878290e7bd307fc97d9dce54c3dd6f9a9c4dab6b988c7163acfa8632c80f8b3dedffc340920" },
                { "ja", "38f48129974d0839afc5259f4d68e24d83c58e249fe767736a8212143c23909b5ed73f91df8a4de001174987a145c923df7621ad1d9444c6408a722aaf5bd9de" },
                { "ka", "36f58d827cbc6e217dd11eb815a16b5d4b044d0fcff16804563c774e0a2b6856c1e14479c0833d1adf6e74813ac976e3724a070878cf890308c230f53543f447" },
                { "kab", "dda22df920da2b07d821e4de544fd4452173c7f574e5c0df7c84dd4fb555108ea600c0693109c0b51fbcc165a43a57a680215d33028586acf02799655359045b" },
                { "kk", "ce2d59c4629cdf7ca786b321b82e66286449ed18418d3f867a802d4a54d17d135d22675313931f85dc0267cc205e2a6991bf910c6f1bafbbf08b34b29a2a3d92" },
                { "km", "e0aa4053629876781cb7a9c6ab9f99bd0aa0dfe8dd6c80ff6befb2f507bff5f24b241e29639f40333109b66141ce9ca719cba1395030c73ff0ae6eb71272baf0" },
                { "kn", "d2470825f425408566932aff7b2c0c201ae4330e0a54a3db33a5c335a88e21f0e5d07f9084ef3725d53dc5a9652f1012b80965bb742e5736f7a4313cb6cb9b20" },
                { "ko", "bbfa7fedde9476bd26c40f5230466ac520c7bf9ecb1ad504f5aabe9d31c416043f308a47dce7ba96a8c91a51ed419b5dff8fcc9d3aa7547d46979dab1c7fa9b0" },
                { "lij", "16103a00993173bd6449f72870cec65cadc85d33b31585b1f467c2657f921f1e52dc2575607fab3cdebdeec2347dac218483edbbb0746e7fdc658a08c350cee0" },
                { "lt", "f515d3bbc58a65f3162b478bcd517a42bc8f56ecdc08b04a275babfc8c73244b7ecc8b2b59bb6bf0ebfc53c40308fa522545656a348ee255417dfd318101009b" },
                { "lv", "930eedbaa6b6fea824e38f89f12002fb8f98321e518823edbc57b4ea1ac14b41a3c93f247dda344953e4b7cad10d040e2feb8efe322f1e527e04092bcd844bfc" },
                { "mk", "5143f3bd22bfc31428dcecb999a979d0f34d67d04b3fc9ec62f206551791956167022617fba75158a6b81cdc3c331e5b1eb8f532464c9a8d3b9714254e4fe46b" },
                { "mr", "8912e11c7b3c724face44266a8d07f3420c8f8e5887e328b0cc72a2ffffd0085fba61101084d9823c6544f54618a93c7c04be22cf2686b0da11c393aaee2392a" },
                { "ms", "7d487b9504c9cc0cc0ebe0affac520bd2235c638b7a0e41225cbe7913f6633406b5843e4e44422cbaa17a0db58dd0bc021380042f95c0e484a7d4dddfdd1f2ed" },
                { "my", "ff6a8bf6753f7e2f7f510577ce0c6c67ba5c03c46411f14ca2537578bb66a5c1c60bb5ee2c1c027f271f8d4c7706ad6ec048d3af9879692551b3fd536806f9f3" },
                { "nb-NO", "6ff9122c2da7fdced6fc20bb28cd6bf13e1ac55f2935d77092cf1f3d8fd1a2184f6976d59ceb897575e1219ea9ef843861c68db7cf87e0450be3c216f49de504" },
                { "ne-NP", "7275e7eea111eeb49ddf5a07a5b80c755cf4653f19551bd701363b07bfafe3f1f425be1820ab1e104afd6d5468cdf380dfa6e8e907a1b4cf127243f3314578e4" },
                { "nl", "c6200ff0eded4040456897c5f56313c13731660211184908408c636f39f280aab08847492f0f70f083b3eff6744ec67abc4404cd6dae3c0bdaaf381b2c6895c0" },
                { "nn-NO", "d937c0e59c40e1d458752042d64e2ad4ac508549ad4127930f2367996bf01b1927af001e613d7b00d435edd3632a155f8ceb476d97ac2f15c83fb2c8518c1e38" },
                { "oc", "339d69c907ff3e10fee2881c658a81234287ee21c3a11f7fcbb6f451edb61c94534523b356173b579187412480e861910f09d817398baaf0568e3fdbb861d7f5" },
                { "pa-IN", "31ca1f9decf9fbf0ce5ad812e72366846fa693ae2cff13437047450eee33b6906dc0d97eaef826a10a8bc7828148094e4da6aa59e33833798f857fafc1745eec" },
                { "pl", "645b2e92670c0dc73b864b80522b63cef71d5f2c39b097c33326e6a16a8960b18e803a522ff0cecae325d1a4b3c21c489123e6655be166b1a34928b696ea42c0" },
                { "pt-BR", "09e44a904d641562286ae1248262adc7f75d699d1cea9f0bd2d3f573c30dd8e5740a398a3a0a0cdd1d0396a68fcd0e2f3e986a723804d9308afabeeca44c32e4" },
                { "pt-PT", "5f4b00f461f07f61006fc07d1ac9f525f280afa135d76ad5357cd164fc032415fbbdbb6c2f83bf1465580c1140c9cc190121cef40335d566c3affd462c756daf" },
                { "rm", "c5a3ca6d42df65c07214225dd2223b6bf3e8af66cc13753eb6f6e8173cfdc45becc33632982661a7448e8c2b4189d236bacb76b0d2ab34124d4d8af8de9c1bdc" },
                { "ro", "e71a2d600ab04e6721d25f368e48709be688182d00bab1974d3675468abbb1661aae1c3bec69af38a4851fc54a1875ad58ca3653e5f667e8e934ca807605dbc8" },
                { "ru", "0b22932c5a9df75be436ea3ff33d36d428fa030425fd27b1ab5cf5922b5bcdbc0cb8870dde4682e5796ff0238c95a2e4a3c7087705a691e3287f493faa646192" },
                { "sat", "a2cb7a1078a330dc6d6041695d361f0021911799619938be3fe003a126cfbbb7eb071eb8c748067045dc89821c5c134ad0938e41c47868cc0df0ce54f049c9ea" },
                { "sc", "d3f992b581eb4789e2087bff9a0ec4ed4d0e12c4100aad0bac51e67768e10f3a651f17dc29abdca7784ffd28d733e65ae87557b9c56c9a3044bf9fd97fc93cc6" },
                { "sco", "ff75ca2b0c7f3037c02a2c570e9b6698e3b7f5a48b5b7d2846245d247277b6a013e2e1723db78a458bb00bb3152030282a9dbf041724db9368aa0ee5570c49c0" },
                { "si", "2d637b50e4b19bd0b5a88c5afcf212a45cfce0844920e10ca8662549fce38986a8ba6bd6773cc41a0993a8a8d454bce68676073da66be40eae1d12d44940cc47" },
                { "sk", "7d66c8c06fb427ed86d08b5def18011336bea8cdce58a63b72e7814ba643307342cc60be55dac60be0b6d4db37a5b8efa8c39df1405be13a8947f0297b22beb3" },
                { "skr", "1b09a6d7e7dcd47f36112d512470b0f92ff6c560f00e1df203586beae592bac26442d356ef36d4f123a95936a31dcda562d338983daa74bd31f191704572931a" },
                { "sl", "9a3b735f5c599b73a603faa3b58d8e6d65b2b25833fe4660ca2f7f9c870263f14b63c37230bcd7180c331ab13a8123093cf313e6ff60b07cd1f48192809e582e" },
                { "son", "4b535b28de4c991701f57490cb761951d45f97a36a2f4d429000ce7a9d33af92b29217a9eb64cea17de221e3f98c393c1491d4682debc6e3e2e269e3372b9099" },
                { "sq", "98fe3ffc8ed903e123b5efe76dffad9b56bb6a2706135ff0b115f2e43e0a9f4ca2c646044e0b9a8fd7e5bf470ec84953e37039c03cf7e387a96a25228201f8b1" },
                { "sr", "902570ba7dcba97cd7e8fadab8081b0815ca0fca90479309130d10197e9ffb8b9dc7ab60c0648b8b42f267955891a465516b8afc8f2c34c40ac24c4eb173ce24" },
                { "sv-SE", "280c4d4455338208cd4295201785ae693f1b11b25ebfe78570cd4767acfd67e14982cc0863af8d5ae0bc2a91b12da186027503ddfa875c47aadfdd3abc8eaf3d" },
                { "szl", "6c18bc4a3f42a0b014cf86887c816953fe6f0f46102de572abd39a4ebbac0daac5584f9d3639e3a38e922bf5daad83eb2970cf6af2d2f4f85a925ab6e700daf1" },
                { "ta", "d00d226e69495d13a91182a1f0a91360c48b8bd9f204edd7911977b6b0beed769c5c34c6e46a259e81eab510de7c211d847f6c0ea895211a713128ae0e793448" },
                { "te", "707f8e6a876deaddd57d36b6dd3a59208f6eea3cc852b6361e67f97ab1b3af25e512fe3a485c1f1f50e3e7a4b136c573ce02f42c6b51b8a9247f5b775e55de0b" },
                { "tg", "5500ee4093f5fffb92cf839dbc1a78a5b1f13660070d8f6f3cebb9aeba1443dddb96682725fa0c0aa5c99442be8f382500888353149e4af876ba0c1c2f968ebd" },
                { "th", "39130205293013279201711ec59333c1c96fc6f78a93fd589a024ab4e6b2744522db51ae66059a9ac1fea8cf7cc1ac17828a89c5ced46facc5587fc3d1a81e25" },
                { "tl", "1585ebf665b654eead34be9eae2ad8a08a52c2a276751451c4ecd79ca750bbe4cd02710191dbaa285bdbda434654df7fa32e0afdfc7c1aee95e653be9f4ea3f0" },
                { "tr", "a0c2282e54032560f11962b85d7b6b3b03142547846e489e4547cba0a7211d104789ded362c6e308d5aa8fd222325d63aa8669a2986aa987906a9360f1961fd4" },
                { "trs", "3faa3690de6d48353aa9777b52ea07af18642178e09e2a1405b1b3889a9acdffe5e8b3bd84e881ad10c2286bdae16fc506eeef58130e584569f2747f42c75e78" },
                { "uk", "5df622184f0b905170e67a1b86fa483db5824a5b11d0337d319cb307c90737a0b98027b9d5f1dd0423cfc782ff3f01a72cb2bfeed1701a7a0ef35634c0165ca8" },
                { "ur", "0efd71fc9926a0f954302fcf55ec1021c42da54ff26235794fc75ac26b44d1afc55208c16bd5b6d8f64a89c1fcf0ef037d8fa7fddc2e27665772343c6b95a4ac" },
                { "uz", "6952d837a5bff5c858d2663fe4d6e4461227c96524f44d015a98793a0f7da4d94034e66839c09878ec8df6c6f59a1adfb46f2591f1b6b13e17d7efefca6f81c9" },
                { "vi", "75525f18ab031679491748ec7dae5074e0ebea8d046ac14b1f0b69f10d468bdd09982e24c1f51133b87114149572ab18ab37d26d3f89891cd606d19aeec1f35d" },
                { "xh", "f1cb32c457316182f86cb8863ff47160edd31acee428ea2fcbc410f001517eaf5b529bf66c982764d2493085b014672eb56b4da058031f4693d60d76c39b4f9d" },
                { "zh-CN", "7f90cc0187f7fd400493a1ada9ee4efc724221302a4f3919758e4a595ce71a64db14d0afcbb510235224cab135b3eba35b944ea30e3b3f49042455ab42bc7bf2" },
                { "zh-TW", "f46288714a41361d47f768080056ba69240ed60d4a2b164b47295e2b33a0ab342ffe0f66cfcb9252e218fba09fa7e46df674a7fdfec3da2c511a8d69ad8e03a3" }
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
                return versions[versions.Count - 1].full();
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

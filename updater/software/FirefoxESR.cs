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
        private const string knownVersion = "128.10.1";


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
            // https://ftp.mozilla.org/pub/firefox/releases/128.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "77383ebc95c463cf0abe2e2c5ef362697f8148558f23f6a7a31d6d351545c10087fefdf3bb36849b031ffea0f5e468d1073343d05f71b9116dbbaa76e24aa985" },
                { "af", "ffacb514484d3baccdbb118a5e8210bc034bf3da049e655e5374087ccbb85524ef2fc655a24a377a0783a54b646331593fe83d610948a1b4a5e7a80a774f7377" },
                { "an", "c83f725d2685bfabcab957f1f45fbea1103feb8bc5e6ff1759030cfc3c8a158e514ad23dc684fe80bd873189771dd21d08cdaf25e478cbf12f913a84458751d1" },
                { "ar", "efc2d25299561dd635e91fe119318c12243bff391c73a130f7408cf1c17808596dc45d1c4170f9c7c75cf4d6b2fbf520ad9254b301ae3b2702e6738c5905f944" },
                { "ast", "9ad990991c916cc8b827e23fa1ce10516e6b389301fa7d6691c2456cf50254c92fa9d5bf8999e8fd470be5a59490a5e113bb5fa80c9b962ab2e71a8990f55659" },
                { "az", "96c3a477f63e0e4f5abf9fb44d17694fa6705331efde00a791b186b56ee9ac5376cccc2c0a9487b536cf3e4bb651aa06c989b6d51cf98449cd346e9dc2a377ed" },
                { "be", "3e56c90e4ae1ffec8a38f187f4436d74fac4b039d685bdf79947593533af6db872b763f3713cc458f0ba0d7eae23d86a642dfb46c0fd9f52a178a4d43a3f47a5" },
                { "bg", "ce36cca1ac2eac9d355ac3683a37c5cc6ca7ba51e33b284a7a84556955c654c49409bd155dcc89f3cfbd0e64ccaa347ecaeeaab82342b29da4f1e0eb7af6830f" },
                { "bn", "3bcd0f94165f36622deb5dd1d2bff5ed4529001c07e3bbc0dec2f0c391204ee531b77453a0c24ef88eebcd700fa3e4c2942562dd8270d2cc2ded2648bb9f4ad7" },
                { "br", "54dcad5c27a86db980d22fd917ddc8ba811cec3974389ac4e76961a4fb9797f26b3b940209f8f6017ca73644e9a54d4e55fcb8e9973789995f77f0372bbbd063" },
                { "bs", "051a8b3ca5b0592f96f96d461a56e7d4d329a55f9c4a05a1ab5c762f65fa42f085774c3ee3af5a309dc84a4c045332808894757c2e9ae4a47bbc34327e3c54e9" },
                { "ca", "a54f6288be18db7355cf8f8a4b86d983346dd45346d0fbeb149a0960bf826ed2d2e7abfefa44d2bf57e2db49452749e3751687a78e64b0869aea4d0ba456cb24" },
                { "cak", "f0eaba0a26cc2b7efc8abb4a5f994954c3f4a9bb39dd3fc841fb3e134eafe9252a9f54592e11726510317d379178856af56247fb03e883adb44c1662dba0ab43" },
                { "cs", "1cb4afc94875757d8d5e62065dbe9c1361a5aa86bb617c7086ffff5f7524f22f505b56315109ea81a981dafbf6481968e523ec2ca102b25e457babbda73d3983" },
                { "cy", "40a5def4dfc88fdcc1a15c62a3b511f97b6b3bc338400b9ddff7f330fdb18c7db8d19d572480063ce654172ebd0bc68b893f69831e1fffc407cb936ff893fb7d" },
                { "da", "5bb9d20debce37789174d2a7e27776015c58bba9cc8475197e8081997a3f0250eb33582c14041c363630d9335ad2474ac6d7cad8685fba361364cda651936eab" },
                { "de", "43d9fc3e08fdd34ec5c94e459a5fa091ef5c52c86a334994229e7a51cf0c40b8517f54b0999794a8f0e7aa2a46099ccf4e2e995d519d2d01d07a1792bd99328f" },
                { "dsb", "9f5ca377d6b0c6303d295fbbec2a15b24a914d44c721a995a78727cfde0f0f4a023274d93081eebd6603105ad557345a3267b1b91972312ef375817b903ea801" },
                { "el", "a27ab5adc1a3d92f4ae5c301193787e302d449f5c375e9519ad187bbd7a24dab09ca3960ba22604cff5b487f21a1ec78a5c9d8448b3c2ecbf520abf5b055a40a" },
                { "en-CA", "f5cfae97aa4bbdff3741bc11579bb8c64854fde7c75962ab84c62c9b12066d88447a2d13255aceb5746f722489983bc9e7f4185b1c57b4b9609346f74f4b3868" },
                { "en-GB", "d6d06cbf383434d4ac3bb6a1b1bf6baf59e8fae2a1c3187a02ef0b1f3d85c2f4f49ed29377086a69948be37a34375fe0fea95b704cfb2ef6c16ebcb38507b189" },
                { "en-US", "40ac245b75658942dd92d1d4806eec279ae9d998c7b537759cff226d9442e405cf7bda96a99d49f99dc32fd4be6aee96a575022104d7c4e96339fdff43e488ce" },
                { "eo", "60e5eda4aecbbc1b0ad58a4f5eaa9a3e3705924836ccc74699131ccb2f34a6806cf4eb8ff7f7746304730220213f33153d88e1b31bc016242fb1572128074d05" },
                { "es-AR", "3332a62b6f2e3e62ee420f70d47b9ad671ed3c57651b57852c73bac006918e3c73f99d4700627af1ed1e1e4512a80346579d8045964a470830593ab4cb65f362" },
                { "es-CL", "4eb9969909dd96f5e2b9275a77e9c404bdf96f6296ae8f702b9ca147f2c3a2fccb9596e26cc6ac64c281fe62e4d8d852d91f3b9fd8b71653aacf3fa7ba00e7e1" },
                { "es-ES", "839a134a82a4e589f76442e1cbf2acb6f1ff332e1f67b42175ffc2b986027b24330451dc7ae197be925e6d67196bded2bd68a3bc87dcd6ec03a03c3c86417b74" },
                { "es-MX", "10ba7276ec22b60cbf32844ec9ed5ca6b14f473a3232baeb33957818eae1d2b1e1122f5e10be528a8532f8c40c01da61761eb8064f23f6df55a15173c70ad3c8" },
                { "et", "e0d952f81d20eb57671a81fdcadd17acf00a8cb5b90dd90effd9a9a0c116e9881e46d0f00b47a194d652c971dd76522ff8e2f5406b37d4720a3d2ca517673479" },
                { "eu", "af1af05c88e40b72680dc9416d0dabc99143be47ae6e657b308c76028df64f72b9a22f78244b0e790ffdf62eabd75bbc7a571dd1aca5207367c1639b069aa159" },
                { "fa", "8ed92cb0b6f6d77082aa163cb1f8ae820a8872b713a1b529448d00e4010231ecb94a5bde2260d28ed3854b84c6e1913535d2c506b924f5b850d65999d628fda8" },
                { "ff", "ec0259c475dbe67f9ba7a7f8612bce67f0bf1924986affdbb7bfbe8ff10f586967920be80d578505309fe779b1788f8c8b948c221214757c75574d898d10d459" },
                { "fi", "5f22de4f4d1bcc954e75e1429b2caae8d617dd7e3abe47101b0bcdab9bf1afb9f768c3b08b89424bb77f1fdcb0cf5799e2d24c3419d7bbc339461806cbe34dda" },
                { "fr", "ad8160a889f10e4008ee69b8e146d85e710f2e21ec484d2cb6200d5cd67aa2ba87581b8f1a226ae18fe7de3dafa8ae97c48ed02e2161711926f90f783678d055" },
                { "fur", "42ba1b6ab23edba5a02e2ad824558db193891f69966012e732d211d2b033395e901f0bdaf26a02fdb492e5dc64d45d6d9d282ed7021f9a90b2c2c58349d46ec4" },
                { "fy-NL", "20ddefc28b6937819ddf4eb902a78c49bbb6da7f217991a63b622c678a203486ecba8a14f9020b993fc0bb5cf00cda2c31bc534572583820eb22fe9bec724086" },
                { "ga-IE", "5055b94171dd14031ef6592c66ec4e208abcae5c33bc7aa4995e05092a997dd6db5dee1c5b30de7004bbe9e6232c451c15274d379e3b63d59ead7fefcad0f624" },
                { "gd", "d3affbdafbc4293e9750a24ed15f44127c9b9086e19b9166dfc7ae129565915583943e95c3f5fd66f24a59ea2c15e97bac5d9b1ae00cec7eb71a8bb17554e415" },
                { "gl", "5926ad657265a476667ff9f57a67088db9d31803283b8c74722df9934f2f598fbef7efb4556734a111a96ca4029720143d2de15d617e73d5061da3f55c471dba" },
                { "gn", "69961e9c0f13d17845537b84640fcd50849e2eab70a5984940c395a673e87078c6a501226c2768b265865b485066348110f3396c499ec9b3675ef9ce1e56d4b1" },
                { "gu-IN", "0187e51925355f5fb586866276653a910c955a2be05ae7860f8f08ec7f38fb7d1399f9525337c05807520f50447d9317dd69b14dede4da48d3df98cd33fb3094" },
                { "he", "7ff211047c9ac1ba3028ff8322579a50ebc5b426269f0111f1b546aa37010ce39f2d4d45b83000d2b4b2c8cf8675079e170d5e60662687472ee089ff53a3b0bf" },
                { "hi-IN", "8b403975329cfe1809dd27c4a02057714f2230677a530ece2f986700ad8d4a12eff83b3ddeea157bedc982d6169fe9f2da0f4583a8ec65753770dc6963c233ef" },
                { "hr", "b8219d363c95f237b976e211c9c09fc37c688bb8c2b5d0b1e04382527b958fd2d0fdb5b5d9d8de9b275cf8002c8c9a6dcfbd501797270880cc849f23bc9e2aa8" },
                { "hsb", "b3e65785850100122ee7dbcac71edfec08ea5ac7de2eb956fd5fc66a5025a1ccd0d69c8670a404670255c8bdeefbdfbec37502d573a4e280c63c5ac0cffe8be7" },
                { "hu", "20e2bbdfe83efde3306e4e061493fe673bad5556eb0ff21eaa91308547ed9b0ddfd42ddcd776b2b0b0150201dff2fabb075c3e97c18c2495324685a88dba871f" },
                { "hy-AM", "3960f57e682638a87ec6975753d6d5bc5205eabae05945775c8c71f1d4a1440d35e511dc44851fc1321313d11b5add5d7e1dba37a43418b7595cb8a2a972c8ee" },
                { "ia", "8fe46f8b62f2c141df7d8e173af5460b2914117f639896f6296b851bc78d94324d56a69cbdb082c2057f5885707eb7a2328dee7fc82a21a5b7c2bb0a21bfae4e" },
                { "id", "0380e92f30bddde18b40c6b69924c3b2618b3ff1b9ca6833e4236bd80333d7097a88f79f0f988ab0f21427dd2215cc642d77714fe281fabb10da25a36749e3be" },
                { "is", "a04d0cf41383c709161ceee19156af84d124a4bacca89275562dcc4d75d1b5c0e398b21b001b03b42a8a9faee2cd996a389ed16fb7b168e5dfe45c5ac646d289" },
                { "it", "b08398adcd053ef0e0d951cb881f43ba8c3f41fd9fa89483d9084ec880ba138b7b7cb6d901d38066623f1db3540afe73c0f1af1d8ea8fbde640e67b19c7f7fdd" },
                { "ja", "4d26e15237d5cd894754d36f60f90d1470cfb268ecec5e004e0a75acb06b771a8ed74c61016001a79b56a5347f4d1646643f9b2ce2a2b53ad5cdd83f89780507" },
                { "ka", "c9a0b9ea999adf825b361d0f27f828e2e5d12d274e2cc32fa5e47454df3d6d7b47323b102221eb48168621ceb82ac07aa9efdae4f58d0a49e3335408333c76d9" },
                { "kab", "fda2499a6b229efa5dfee4da2092777f7a0c4ed5a5b4d32251a3767deefd4172aaa6462121d20f5f4d384ee2118a4e399eaa7969b275ee43b9cbff6011f45283" },
                { "kk", "6f0c2119bd79c8e30d0debee76f95bcbeef2f3513f40787ac53a87f637b9d1ae7f741fca3fff40ba549e382dae850001d7a29fc8af5faa90dc0054cf96ad3542" },
                { "km", "ceab9a8c639610266ce2902d480c9782078b32385955ea08629bdfd69de3436f074d848c39024eb860f6b0557e097ec9d8471348416685f9fe271101aee3333c" },
                { "kn", "56c74cd4da17cc556e0c1af06b8b3ff1caa0bc735ebe9cc6e52137e0d777ab8b53e6f39a1dee8bcf75c1c7d952c976061ef0b7ddfe6daff0cd6daf26f61ba7e2" },
                { "ko", "4616eec594f4c9e32a10c8ec0901437f730fac1ad174637cc9c670136098d8a9df487d4112f609c530b34cc175930f81a569d0093ab01220ba837f710c9aa361" },
                { "lij", "441465facd19ece67d06399babbc161acecc4786ca61c7f95aba7019957ea5619333febb89e585a605a2472af8eca254f66c48ea708dceee692b06fe1c580bd4" },
                { "lt", "9578bf593baee61c56ba134a21d9dbde6c6bfd85458419a3efb1e85ea8bc22f3668093c929e82ce362c00992290999ad5f68c8f8ea7aa9345c3bded210150a80" },
                { "lv", "f8544cd7b657591b8da871f59e691988fd5e786319d49981ade4d9e20d7dea70ef0d4998573aaedde466c2f9003aae1336ca5e05453568d75de1064dc45185fc" },
                { "mk", "8bc893fa4ed43e15419a555034edcaed9cb8cc2a2f9e1ebfc2e3ed72a67aa82b02630deb22223e50d18a8f85fcb92bc1be769222b6c3c669e72e61b6ecdd55de" },
                { "mr", "3cbda58be5ab86ed4816b2ade0f67803717509516af5c8537db22faac037379eea600bc6c3010dd45c820230d4d94e296bbf5a667ffe2e37ea57fa7bb9963be0" },
                { "ms", "a75d7ac4b5ecdb4ab7922d79de4430362d91f591b35025c9ac115ee52512aabf4fd16b9ff55e71e8ce012882ba0984275036ca8b4f36de9ee9cc275b6d7fb5e6" },
                { "my", "86fc807e21e5d3666e1bf586550be2faa6f75965d26d402b81d48788a3361667c59d1f7ec83bad139b0849d8de25a50cf96435adfe895b5b9f8eba5f2c9824b5" },
                { "nb-NO", "db9179f8476b494ebbce6112e3d4b41b5bd6cdafa028983aafb169e9a022bd2c137f43c57ca900f29a414f1f77c8e573e54560b5c2bcc44481d7588d7bde2738" },
                { "ne-NP", "02967676b3f725348f4c94bd619864b470dcbf26c36a4f99cac5314947734445c760af26b1bd2e4b10af1e713e8a457f962550d71eacfc74f0cd823608422342" },
                { "nl", "18185a7b01f0c1f8923bd1b2ffabd8b8e26054d640bac078f668b282567ef4fb0e46af57f59e7a371c411c67e5f9162449c322885633db9f033ae69483ed96ed" },
                { "nn-NO", "e88a366dc3cef7cb2c3d0c25e954b0b6866b0814b843921dbaba664f9d01a2e842046a3f48365dd7316356e419ebc55a4e2dfcbb6f331749d33cf58fb7fbbf1f" },
                { "oc", "f877e5c47ce8b90565f2c19954b1277f9c1f930e5cec8ee6f2c4044f54d822e48f803a1a9a7001d092ed6133e37275da0f974532f99083ef51b9d3f6999bda14" },
                { "pa-IN", "fafa03e76f358facdbc985cb645bc464fdc748f00af3b55b41ba8545ce585bbe7f32477246df5eed4d07c568d7672eeb0392b41da78f3c13827275a178aff125" },
                { "pl", "e62e075f9b3d94a05b62cf61cda88257cee63b3867f99f4cef8cfd4e4aeea49a263da04a326814032003133b1ba5d9f0ccc875d5c4a3c166d9c38868a1bc13b4" },
                { "pt-BR", "90ddd5bd5daefc5242abba1ac5dee92735f28304bf73b3ca8dd203663239729ee5dbb34be8abcf69470bdcd7f5784ac8c302bac785adf14d01d0d39cf57c1480" },
                { "pt-PT", "5ce955969ee3e3eb31b99432124e505843bf79838585eab48d18207b52de24e67fb8528569d892c28a5e46edb4512b02972ef5bd4a72f564ca148f8ea7a0049e" },
                { "rm", "5e53a40e941b5b2987a0d7b1e08436638c9af2348a09349ab1359d443cfeda11332fd8380d7aded60a00269a72636f131af69123fde7644e1a352503e4ad0636" },
                { "ro", "5db8d6d26419bf4e4bf9ca16d891116c7470e1f5651f2fe1cc0c77161bd3f49973a3f33777d1cbebcbdc23207612508fb0a8d065867cd5f0fe566abc883c9706" },
                { "ru", "bcf9b240c547c4690c5bdd24a33aca3788cb820674e9f047e04a1ed73602a56aa420b1b5d2c437dbd8bafeeab6af87bfb55afd5c84cf3a8f84b9031a50982512" },
                { "sat", "d9d745442cb1aa56c1cfed50edbe2af2c3993fb2d9a992318af320b382f24d9d5337bcbfd28a3b7259fd3998ead3b9a0f7263b1747bfc4b89f3a917d0119973c" },
                { "sc", "b6f5f30576994923764d4b106fe9cd72793a763fc841b2d5b44741b39846b6f3dc944f1e89675beaf4c72a7492b642d4c056dfd11e08f38709f653682c07489c" },
                { "sco", "d60bba0dde90d07ea91d9aa3ee85d13d6ed155507d3e87c929c5f40f23d5f7b678c1de60fa9320debcc18160ce81826f0c288ff1c677e682442eb9d96a811372" },
                { "si", "a7f8b704fc29ba7f487a0704d869ed42e3c9aa082a2d3f3995fe108ac93c0fcc0d8668c0e14f8ac04ddca13d06b5a7104078e6ce3b8a6641848388378b4a9d9b" },
                { "sk", "d81cf9bbfc023b5698b5624d64754c43a9d094657e2f5a582ed9053bbef7affdb3ee6e972bf3211a4297ce2e58033932a3b26add4a43c492f0c46d7e510fa67f" },
                { "skr", "6c634afd3628cc45cb70b7cdead83938ec4c724e75f99abc5b2e5d0e07a07ac618cf632e1c9b8b06d698258938aefb48f4071057ed74abe228a7af7f28febc49" },
                { "sl", "d7c8a4c255d2b3342cb42d3d5dc674ac6738f9eb8ee144b608df907c4b8685c896d7bcf18156fc01d58fb1363aeeeaede15185e5d778093fde155854661dae80" },
                { "son", "6af66547347f0b720390b93955e1f4e0fb8d5ed945ee10f8aa6a16edf64f05233a99ae8421cdda5ac8eff0f04be679424b98127e42002edaff64b7e67d534874" },
                { "sq", "d9e1446c908da86ffed59ebdc8717db32d5cf2d8c2bdf1310e3aa749091745744370b73b1381c214659a1d9e8fc8d922b5f9d3b8e5d7c5e593648857d5d07d03" },
                { "sr", "c588072a2be269bcbbd159c5682f973e5897435cb381a1525cea0eef6bbd6c50505a49154a4364da5465e327dc90d3242338026e75b45704f2b00ba371586adb" },
                { "sv-SE", "6c7883dab7f170a699a5d062172134b1fd2ff19edccec867b629731193dffcea7ba1298ea0042a8995311e47b4fc8d4be7317221a2635effca712d2865657ce6" },
                { "szl", "455477c232bbcabc5253d2312fb0aa03663eb2e453597c9c34c5d10b9854936ccaf4e851f9b97f5a3f5a96b720700ae3f59c718cfc795fd431a27e3c88615ef4" },
                { "ta", "ca32cd65b6e86d6e9322427a23ff32614adb5b969fcadc8b15d5f9adb97ee25abfea55cc83bdbfcd3c04abd1ab1379bdad352a4bd6cd8dac68162cf5829fa91e" },
                { "te", "04b3cbe4720b5a33b2a65eb3b14644af673b665e39592bf093174771f4ef13706aae30ba3d6edeb4b690f731a643de3dd39f030d93470c5d6f0297dbd6a24db5" },
                { "tg", "3cd8936d61fd9dd1b7709d01288f9e943fe3d83aab4967f77221c0ac99c7e4d06b3e4f67fa283a08d30b636cbafcfd6da1434f94a89558f611ec44330b4d3c5c" },
                { "th", "a9ae08ec3bf8619df36c9c0f5cf0b5f0cc7c3643f6d833c9349876807780455f384da00af5aff23fb73f31ba5874a570e6b6f27620068c14cb35c7395e3f2b61" },
                { "tl", "652d625e25a3055be49f3036ed38c21461e76cbb8bacb7b207bc46b40253be0603e0d58d53405b8e7fb769e71c5ea3dee4c257f38984fcbd58bd6eac71c02932" },
                { "tr", "f8ee358138cb0fd9316759b9ea80102dd4286935061ab3f4293da2b82253243bb7d73563fcd553dcaab5abb914d6529128cbc4f372d77e603d756e19cd9d181a" },
                { "trs", "3854fe0412be76dbf0c00a258ba0faa00bdbe6d1a81016f3a4dda5b927d5cb71cc4557fdd0054809cadef868e5a028517c8181ce6f7b66a33e6ffb9e5726ffe4" },
                { "uk", "b93e1739cd4e34a9f96a4871dcbafe7ca678cd3aa9ba37338f08435fb127d2188b91d04da7fa0d002518175a4fc9992b00c193d7aac8c25c6c1904b7f83fe300" },
                { "ur", "1baaf34f1b312260275369223c254bd26fda1b4e2711c8a41002eca9dd66632d8b13b9314a386f6c8de4899389ebf408a0b2da7b0b148cb11a3303bc5821a711" },
                { "uz", "1d698e4263e0b1cbf21e92d3fadf9f062e66cc22b88df969f4f6fdaadf9bd61211a921161f3f5fa6f1c32ba141b3e07f5efb33968b242ba2520ce64b8afc247a" },
                { "vi", "aeb84e26ed2a4c5433e542a9aeed11bfd9af34433bd50c31fe81704f20845b4df598e70196f5b76d99aa0d03ba69274f528ca44d8953195aa10e33610eecb17d" },
                { "xh", "61217b47f211abe17a0470c4072fd428d2f809da2654094ce3d0eecccb29105b44a95d1378b0f2dd0b9ce682b24443a5c3ab18a1642a5eb39c0cfd4e5a56eca3" },
                { "zh-CN", "9237268245b0d6570e282172e3c21db19bdca390d349089029d96d950befbe699f17bc8243836b75cf2def8954baf9f723c6c753e1e0762b82f7374cbeddb38c" },
                { "zh-TW", "edf9d5d26dd65710f968b393017ebd12acb854678d5f82db21c62e2741b624250d7cf11b74f3d9bc10fad1c201e4d1e49a69a72f7ec06b1add83e355e84b0805" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a387622080f0fbae2e7c9d067fef46666cd9e1469c091ec696e20a5eab4d7e164731bcec4c852125012927b13c1bd1b5788759214ba3c570eb787e3535aa1b03" },
                { "af", "59ca040ed0c92cf0c5deafdeffaa449b528181568df2e8808783552e8605348f2972f58a4043dc2fcdbc5bdf6b3d7bc60acdbb4a0ed4d578411f9699e896af8e" },
                { "an", "72e856e269fbd966cbaa88f7040a16fa9747ad7fa7ee219be00f78ea359fb2ee2337d00b427a935d1e475554b745d35908c23c4b434576162124e81405f2abe3" },
                { "ar", "2c9752e43b978b5703fff8cec1c3da95969544a800bbce999aad64547ad92b763afcbd42384287cf95c51abdf2fa726101a70638e86a531cd4045b29e22f7cbd" },
                { "ast", "9ab4bf0ae5a95d1ab0535ba19e3933aaa74739230be1283c99f8361e6133a57070e724c5b0707d879857e73a0e94d5a95eaa2f7c6a8c73be7e26a1058badce19" },
                { "az", "ad25fa9c5a2f9871d9bd08e8d75015c2a4142d1017c935d7014a413037b984423cd0b7712e9e85b3ad4fad671ec2cebcbdc99cfbe0f8510acd65d2c465c8c9ea" },
                { "be", "898f1d3d91df66c1edb4e1588e4bc83d834dddb3399e922250e05a9448c6e2ddc1b42086f5a64149b2072a74bdaec2759ddda05f67a391ee488691766bea9f5a" },
                { "bg", "36c64d5c37cf20fad1213c6f64bf5adda66b00113fe4a8778e470ba974de2754ba7f2ed393002c15a7c35384b767b9584f37f7871bb43170f4de86b9696f5f2c" },
                { "bn", "ea0d806d459ffffe0a6b3c8d85b832755ef1b0331b95f7a35ac6606b9c4d90a081c64e17a312d0b43095ae100962de8d30ae7df15dfb97e4f31a876221fcc79a" },
                { "br", "9689e2863f7c31c4790e9aceab7b209aeae4e2272a0ee56401534d292d60758eb0ea4c676e91ccf08af08eecc58f4702cef4d54b767800d4af8e199896257cfd" },
                { "bs", "4740301bbb12b6e68daa92e49330bfd7bb13b32711ff6f7131127cdf6bc5f89e4adc566e26c8cff9c0678cfe746f753203b25bebaedba29b799b379730d03854" },
                { "ca", "574bad964b6f7ea0f69ff3d87b5971ab044ca4a7196433d6464456cc4c22e569d4cd8130a3aa387fb670fffdb479e3a41775ac152f588b99c5204c1498278c9f" },
                { "cak", "18721fcfae5efcdc4556bfd40b06fbc596cb82848dda12231da1030c5c1c5c1137c3ca1f2d8e6c3fdc597891733f783f4548f5f58e75bc5dde7e137a9f3b631e" },
                { "cs", "8deb702a63ddfcdcfeb91d7d5aa5e5b90aee37ef71a79f7b6227e6d0bca82cd9fe049c8fb857723f5b04541999924e256c7bd09b338bfb05fe632e0305b02200" },
                { "cy", "2a91dd2d07d8a82e8746f46f8792867bb2cf9af0e7e8731388bf6e4be36afc865197e1679cc7e52084e20a468a2cf4d9e911347781a233c5ac831d7246cabf9f" },
                { "da", "0f1d9ae9acd58e2217691a938b7a6203f5700ba55101b5e4bd716a313e267f2bfa2b0a51aca4297a0cf2bcf4ce34e93650a51f82ef17cdc56e17607b7e903302" },
                { "de", "3cf00f73631468ce823ab126a93b2a77287a7ed20a2b1cfb71c7d51da60db451ae26522f046fe43fc51458fd9b2fd01a2b8420db6a117a858140d22b0ce3859b" },
                { "dsb", "3a159cc3c31811aac24d5f58a5bdac49e6bcb5880889e78be34113bed3b435004623c8d72911922ba1d6e764a6c86fe3b122d19251fae96bb9500a16789bc4be" },
                { "el", "4a8697ff21bae8dfb7e537ee95312693c4b9bc08cca9307fe0d7bf31fccd6e8fdeeb8af074f91158b145af819a751a7dad4860ad747d2150817f7b0e403740f7" },
                { "en-CA", "327f21b7cb005c4a034a6995e11484a7c11fd6d7d22976f26f1969530999eeb7c1ffd3f27a4b146d6ae50c992f14d96e464dccd42405a9b0cc5352c81a7f926a" },
                { "en-GB", "9bd81a3bd2cb690a94a30c1b5577d82d74511870290cf27ad0f70dfd7ea984b1ca8ad29febb14bf2a53123d12c89c9abd515dcbce9525812065485d46669618d" },
                { "en-US", "1e3fe30160d4f24cb5d56e65c2fc834a9a1294c3b21e2375268184860c8cc831a205482580d85dbedb49e81ea37b0369c8606ed5d08f543d6aad64855cbf0594" },
                { "eo", "e0058b38286f2a771f1b16746f0df2fd17dfe27950809392a1b4ec63af4a0e84d2fe8337608c2af6f540f490283feff31d6ff5053b6d8ff328fb0d3129587e8b" },
                { "es-AR", "58dc2c64e2bfb79b62bdc7c5901deba45519e3ad52271f678dda7bc38890c1dabe5e5c6f7c4a597c5d51f2acac18a0d9e340fe9602f18c549e7372b0a4d64f53" },
                { "es-CL", "4b518b38086780c57a9ca03eea30e0009dab6003e3903cf1ecbce88cebf5b4075fd9c96cb32dbd9cb2ed26dbd7754b09af26d4e320cecad9303e0733fd905935" },
                { "es-ES", "b1b71d124db46d0ad4ea7c859d137b15ad00e39553ef084d4ef12413cce083c1e78e41b7c1153a70bd76569be7f8c57fa1b391a288020ffd7695464763ca30d1" },
                { "es-MX", "c765d8356f839e6e5fcc46ca292facfe7123681c5540cfa7d9404d01fe2f2776806ea5534b067b496fcf649b10e1695c2aad8ad74472a4176779ce73575ebe64" },
                { "et", "def47e2cd44906816400402dad9a7f8762fa40e3b029c325a6b7798cbb1feef8c066b943e68e99237804b98c4df95d72b6223b1c4f3be24b9c84e4beeb9582d2" },
                { "eu", "b759039842e7c83722abbcc43edb0ebda2d9c4c711c121d71cdb733fb5a7f7a53df5fc8284de577ed6b1d307c2377b25e4a2fde4797acb79608db3071e2f9663" },
                { "fa", "d2cf6b5e212715b278d71c5ea83f16e087b3a82fdf84c277a5e58228e178b93349f4ed81349651d118a259579065ef8acfdb3e99305fdca43fddac2ee330115b" },
                { "ff", "1365410c9c8a60d720e6f9735922f852522ccdcec9b609b80fafc694041b78dcf2b1077e5f342b53ff25c53093824f800c4a5db1ecf83a148b05bcca2e6b34ad" },
                { "fi", "6ff188883f36b4a1f629030e8a46bc09af1a3e8f8a5ea1b640404b4cae5e8540540cffc3d0734ee611b23dc03fedd34adef6aada23ed45fb091d2a72f92524f4" },
                { "fr", "27ac6851ed52359708d19324f4787559e9162c6cd99850af3204d4150377290695910c7937ad6860f9519a489b748b58d9a495514c874888c51c04bb59bef00e" },
                { "fur", "6b392afecd352835fa85f01fed8e61ba9b0b39e12cd4f4da3b1300505673a6411ea76ffcf1ebbad8dd86a0d2a84ed2f3e16a2e5cb930a8dbfc0ca5d0c35a4738" },
                { "fy-NL", "46650b37fa5edfd4d8e4e9606f3a97e744fab0ff2b9f9b6fd27828c6bc900c3da2ab5dc5bf9c046ac4cc2fd566ac3429e20a36da89bdb88a94111e38c3a87167" },
                { "ga-IE", "0e2f16602ffd3e08089e1022097bdb01f28420330a5f2ee441a502a81c6b5641bc2267404e4492243542f2ac50b3743405e86a738298cccc76f146cca09ff986" },
                { "gd", "4f6af4f0b692f721df78810529c768a196fa35a2741a61705aa0a416622e082dac22decbb06d6ef327190688e61309c2e84b73639bba8aeebca4a21ebc17be34" },
                { "gl", "4ea24b6d7ed7f99cddea5403da6f96054ff7484e4b77e8d13f47da4d90ed933aee5c24eb4dc9e27601ac046d4e597f10ecd277a6aca25642c461a1ecdf00d509" },
                { "gn", "6699079dd0a2114e4a3ed9031b2772a7b76653c67c53692003353c42080a49a7313ac08e0192bd63e7012eaec846346b68618151aadb35dd6189020e73952bee" },
                { "gu-IN", "6ef658a849b6d984d1d33d83cde1a911ac01c2772acb6e1c242c8d3b19e7f764cd2c2526231c44e3ed471b237c9510158ce5aef165376ddc48139fae0bb3ec22" },
                { "he", "a5b1f17a677db527a6e2456a2f9d4cab0167cf51f7b8aeb09ca28e076023725f890a5170cf0f8957395bcd56a6f1379828b2bf3023b92b0f30523e2a050b7735" },
                { "hi-IN", "982bb48b006f8142e27c6e14058ec12538cd4acada6b652c21554d53d928673128edeb2e32bb7e61713b0318e40956035f5e7ac04f5d6f8e5bdb04fafb76255a" },
                { "hr", "90b25459c17139bdaf0ee1e3583a5b4c141eb1e23ac5fe16557e6abf3c8556e013d51b3ca2aef29a5080f8f3d2c90c66ee83a5b97f5a0e7e5566412a386b0c17" },
                { "hsb", "d05a69d7965f88760bb9fc96f076d7dfe636732cdf75c8a3195a849778b5d60e080692f2b047eacd54172aff06b4ae438eae4178e115fd6cee11c9f7a8892d3f" },
                { "hu", "858b7bf407613fce7437cb72b45f38573379c5260c41af471ea4e8367238b887d7ff75b2f8a9386fe10147144233b73de5e8def2ddd8e82c22c4b7c704b76df7" },
                { "hy-AM", "66fff2429cabb33d0018eb6b3349af030234699949662ef45060beea14ea399804d536257d8983564e43387c7f8a264b7dafd14eea13586688d8b66af7a5e5fa" },
                { "ia", "311ef39051a7f6debd2fbd2dc94a7f8e0867b002162d97c903627034ae23a0fc07f66f0d08517617c9548285f575e6bf7eca06de99cd8da3b9ffee95c1c182d7" },
                { "id", "871e4609da102e5c81e65db3482e78c19e5e41b2badf46fb1eaf2fb9e84c5cf1a60e58e1e51e619794cbc9668d6c669bfc8d49f8179c165b085cc1ef03856763" },
                { "is", "ef1a36a768fa8ad6576ade13fa990f483ba1a000b7fd07531e12fbf1196a79d8c4fb0ba1113f8d42bdd2a272b728437d9798cefba8e43564729ec354aecef363" },
                { "it", "c0f57f1617947ceb5fc0ffdd8ea7f810e703b748603dbb0130ab29e57b705bfeae0860c25bdf3d7d79ea8b94b740c2ad9144b44e9ea7c62eaa9b7f1988af97ee" },
                { "ja", "75620dfd3ac8a4d719eada468543e1fe8bf36be50e35f929690ee349849616e4fbf389ab5d3a10ae0d1d5062bd2b80b5a4b9e534d7cd6c5ee038e0993656c9af" },
                { "ka", "bbe210452b1564944b462c6e15c9328f8532a66bc2146681b5dd586d00145902e76f04d4909d8bb4e1c6c98c7303328edbcd602cda176c5ab65f4538b8726a7e" },
                { "kab", "9264fafb4e52b9922d711abb7ee14850e69c1c7cd7f7b08725411c6d9dd95c07edeaaa1231d589cdf57da48e2e65beaf5e31e57d19c089991605226cca0f59e0" },
                { "kk", "3a311a57c167d60c61e9d5bfe362a60dd433167f1200e62e46151f3a8e053a62057abf7dc2b3f0a4d383d9e0205e2c1b248c762a81ce4c8806c8d8b93a833936" },
                { "km", "b47278ae2e85171c49da2ec5ed1e9064e28e50281deb22fbd044ce6d9063b8bd3f502a44bb40414904e85cccde8e5c8077b3998498714db9e6a79cd43f2291d3" },
                { "kn", "516fd9b719a4cbdde6db5008af4d96db475df090031b00cf65771988387f07e5bd35e958581499100a16f4047e659c3ab673c88ad153cef2ed82036da6e88e58" },
                { "ko", "bdca5403b9a97b65fa00720619d341e04ecb1556410e20f3608fbedd22bfa6b5f56e4f1ea6eef9a4fb399460cad090d04df81538e78e155ebd41d4924501ac8a" },
                { "lij", "f37d90a44d9049a39ed66bd1bdced817434a8ec5206185ef9a8cd909dc5e0fe26a2de379cd149e9a710ebf80e05643539919e4735932897ffdd58e57fb36c64f" },
                { "lt", "eef9024dd623905a210bca2ccb0539b5de9d30ba34817026b9ed07b7e6f2ae9dde1ae4067b2e942c42cd76d1f4929971161faa083d358963a63fd1db35b7bef7" },
                { "lv", "39d3d1caed3571c42ce8142aad68fb9f0e07e77c5ceba6380a78de6db5dfd5084c170564146e4924555e1c2e5d260db4153be961dfe934b37bc13a1a781d1d17" },
                { "mk", "7a45b8afcc51f7ecc5726f1ce7e030fcfd3485d2e21f2b87a61f8ad2eb2e89beb1a46e6a8baac022b92b74474e48d80a5a13df010e05cad6a7cea92fbd52f518" },
                { "mr", "ac338609b18294f92a6858e88540247e3e35c5a4953c22dc6b9019ae1f5b44146bfcaae4877b7762b84f6151d37869a857a0a174b725f50fbc4b0961398265b3" },
                { "ms", "c9d8be96bb0b734285eccdf7acff8a17d3539cf1fc919c599a2b5c4aa9cd8edcd3501a2161a4f79efbd289bd2a4423dec88251b9a38729424e11ab78a4a28632" },
                { "my", "78c7c349af00b10056fc8ff5e83339b67f1c11c820bc41e9e0c87aa82b76e651e23dc2307c5d65ddb205d2082a5d5a496b12f4bc26fab5231758c5cac1bc9ab3" },
                { "nb-NO", "0233b0c3e6dea4344a790cf627a8cbb252cf1b5a72a15b8f1b14e9d55e36e525a55e5f12db1541b798e6adb42330704c03c523b022e70d935f9fb7011052be47" },
                { "ne-NP", "2dfe16c955114557dfe7f0e8ec684063d2f9db6bdcb55eedf8816076b7a14ae0bcdce6afdae12888f709da6adc69b0560cbf06c099df3735e9e6d56fa3e37fae" },
                { "nl", "556346478952c62c8d90e082027fb319a83e8cb74f91cf7d77134516e8bf3b58d552db31f300e055d7ade8cf9a8c8cc00330876ca520496931871800ef757391" },
                { "nn-NO", "a7f4ed3660500156b8843c115b8669d088f8bd3f3885345e361b272935d95f06c770b66502a46458f2328958237b1250010db56a8ec23f75c4941465560cee92" },
                { "oc", "b2f3f140ea894586a62cb5f30bf6ae9e75e87a972884f9780f2e1226a44b81f3b74fc89991dbec0a04bcef41f8ab5838f191d855a9c48948a04b77ec2051e707" },
                { "pa-IN", "2146eba7538ad5dded0c8d38e694a48a8c99e0358704a9c95f20c380bc8967850d877fbf3911580d591035752a49ffdb80a4649c6e246140a2fb1359c830edc9" },
                { "pl", "48e88d1b98fc8ae2bb2ae034eb51f98e2e22d835b7b9758db347b576228061da020830430f3a296ba9c0e101f67769bddb730040a8737ec7f1b4dc986fa4f293" },
                { "pt-BR", "f3b1c976bac397f49f8d32e5c1fc50af4dd96e08d8790ed50060eacf6ea35de0a1c49a22be5c4f99a3601ff7b025960057a7031fb352276bbe2098a9a4a361bd" },
                { "pt-PT", "637674cd008012299ef1ab3462cb4ce3dcdbdafe4652f4a7be3ba692d64a7e85cf49257e2da2eeef46c3774eaf5c309b5af81ecee165aeae3db8bff85adb952d" },
                { "rm", "cd1de274d64aa077b4e03be041c19024d9b141401955ec4cce1b585c6878a77fe738877818ab535a3cae30d790da5bf3c4c43b82071261b9ec024d877a5b84e3" },
                { "ro", "c5f6d79ebe88a90d0ecc03ba5d068d85062a78006674dbcca8d4248db93e72a65b3e96ae6125120be2486a63a0ea8ae05222baa7203f084401f4828bf10ab553" },
                { "ru", "fbe622e45847c2f96626f1500cba92f6485a77bf06d4d6f45a437be89f8a9ef4fdcaccf906cf15d3bb5ada812415e56c232e26da5b65a8a231505ee93badd9f0" },
                { "sat", "f51f1b3b8ea5253e33b2ce5626fa9e3d363aa0fc87f74be4495090f550482e650523b2831181507be63165fab8e5ebd11f03a0c7b81b453c94f00027bbb16f04" },
                { "sc", "2a653f175aef22946cdaefa613a800f6acfe54f0f62cbeb428d04de5856a688f587188e8a91f975a46d5cf7826149bbb11e89d8ed06bf4e80ed304c578f0727b" },
                { "sco", "f76035a81ab290fc72b0f821cf747ab0fac51b6b3b0ce358b1d5afcf77ffb8eb8730c863dffcc7638e794e2ca00fd3c3438662c5251e7f6d1adeb44079b72ee3" },
                { "si", "0438041962b39be8dd79906e793c2a8100ece49fb403dc8c67070f62d843f5ce9bbd482e6337d6d9424182cb6702ba2bb3999d6a786df011caf9e9c4f7ba9ae3" },
                { "sk", "132d3d2951dcf975bdbfa313ce0a50d1934003b15f4c2711250957b95dcb6f072534d43e73609e206c83fdeae2c7e34a705f99fe152a8837ecb495390ba50e03" },
                { "skr", "9f0961a55deb03d6bd8c8b76a6d63e27f496ca337ba813bc82161218ab65f9d30421a6db45657c3ff2e8110f46d5137768d04dbec16127becaa1552c29238ce6" },
                { "sl", "5adf4173a1d680c114dda1ada20f3c74ee1e2c6369008923570062814575f89203cfadcca599eaffd52532ab41a407026b53c1654eec0a8be9c782c776068a97" },
                { "son", "0e618c864126227ef03d0f98a0a01dc8c67435ea97bba91c571d868ecb70866193648d44c8da1ec68f0f17e7c51db4246b86c84ca96d76516401d91f7c58a155" },
                { "sq", "634a4ec09cbed895084a9091ef12ccefb3be7fd5d43d1130bd3b87616934bcc13b84a72b29a7a80dbb194e834ec47f86f863b400d6aabf91f9a2086be77103f3" },
                { "sr", "6ce13c4a2bbfac5c9c3a80605c74bf830185b3c9cc6f8d50e28949d24db07033caf06c8c126f08ad6c9613c345f5af140a6f89d64c38c2cdc8d29c193d1a0af6" },
                { "sv-SE", "367cfa88d8187106a6d3f44f96e372ef0af16f531dd8ad6002a71f9afa2cd5a7bcbfb969ee641a4ab94cf01f696b75009eed99848110b7c5b1c2291850450a50" },
                { "szl", "b57085f4fd6d80e27630e97752c1581269c55fa43341532189fa8bd0577f85401dea52328dc1fc20111d23f472a2c1c78c1c1a9a9e35ca6a7082038350133f8d" },
                { "ta", "4f9d696c0436feed934bb5a2901b928aa702d45832c046a276faef5bbea45cc877a614ffe672f65d406818fa27b5f71b7ceacb2760157696e15cd855ea558905" },
                { "te", "761c8be2afb88d597b1b88abfaa21096244a266b78419098e22273916bb820a401ca38c0b5b4b293202e3bfa891a41edf775d9085cb627bc7e1c6cb8a46e0b2c" },
                { "tg", "09cd038dcb519ef09daec879be48358f013907ad4a731d960fbe2cc06bf29919f959b07fc01007b7f065d9575ab7d0d8b0c014e75396108e8ced3b5b29cb1c14" },
                { "th", "61296cd32063e5473e2bda067c9ae37ef4932fd073e7e6653384f69f3b0552b0416d5bb565a80b56a04fdec9b092611a89e27c172ff8a86fffd6d23a2886de2a" },
                { "tl", "8e6c909411b50cddf3d4e9491ba1c75a167f8a8f7d65bb80ecc3d12e8ce234d88e28c6231239764a40a5ea280511103b7ebe2e994f601501f06ef89e3d609494" },
                { "tr", "17e62925cdc4bd8e08572688f309925ac07a5d4c7d5f7d800d10322560886892d0675bace2b3fa02b759a545da6b945b54d67e8d2e32892b09eeab0edd7c59ce" },
                { "trs", "cfca80d534e5482d83a6bc5e320c7514a5c154149b26bafe33b5c144a77c745b8647a1f786bd334554c5279aa2b7eadd886da6aa40b687e70189b7c84aaf2d35" },
                { "uk", "978f846e0e8617ce74ab476ab9def92bcc79ba32042b9687cb4517c3b7343712f420f623ee5883960194368b5139ed285544929d7c0c78c2374616190b44db90" },
                { "ur", "a721dd53963bc14831adee39094068bef55a6adbe89379b329b68e98e47af16b455611fdd9012f8fd0fb0764dff21ed69391a32b7149cf7261f263504d6b3e40" },
                { "uz", "4ce7cf30bdee6116c54e807c1d1f9ed41393e6cc593f3974245232e59aeddbf305ee4196035bc303c66fc67b71d1ccc75eb29dc70c7afae213e99ec5ee1841ab" },
                { "vi", "66dddb752148870f41980cd2f3466b5e391455ea377514a96bf817efc088819706831bea89334123b69434890210ea2aa122056b1daa9e338bc6d0528c6d3297" },
                { "xh", "3843be69ad6f7d7edf3070197618af93a14656d58394b91c344023f89e12be021a059b6846df04ecd6ef5aa3a836141e2bfe960d83058bf3a5b764552c042a1a" },
                { "zh-CN", "31dd25d77f8a3fc8cb5882c94c5afa46b343d508bf00ced1b624537e9f12beb7deb514ad2afe74f057e5ced070ec3ae8a5ee621ae19fe6539706983124777f9e" },
                { "zh-TW", "67b7acd0a8c7dffd4631b33df4e96b6918799019ed7bd0a73b3d634d3eae389fb427d5d8a0ae042d468c27fe099a9f10689a425dac690c468507368a599cacd9" }
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

/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Net;
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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "91.0b1";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/91.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "7e2255c8c7b53468f58b69f2218c11cf728b164e869636bdcbed377d80b8137ebb9fce3a7877792c04b4398630b666525e0625282b3c24fa15ea131db75259ac" },
                { "af", "531c41b079e5b9351dd3a3da1c14fe4eb81f5fc52fbbf7f9452ca364f45464ba98abfe12ffde1c52bbabfed7863bb562f1d37a52fd63680164242c3fb818525f" },
                { "an", "b986f71908265c244a8cff4f81bf8c0115c61a801e8951220cfe66d50d476ebff43efa6c0190eabd042e0fcb17446cfa6cc29d2469ce92cb37a08ffe42ddcbbe" },
                { "ar", "f7a824eaf3887ce5dafa7e91cb6ac2a61c7ff4372576cc0119ef471d2f97eea1bf3eabb529b5cee695f6d127013ae23015bb03f2ed6885cc77dcbfbd93aa514e" },
                { "ast", "db4ad4c2310141035cc1da9c549d1a0045bc9d06626d6c3cf97f5a500a643291af4d656e6982e90a1047f768815ac89a180a9357b887cada737baf56b05319a8" },
                { "az", "bc1d41615460f28dad00fa9d32675f9aea541580dcfade29b8efbe49b1f85199897af60c7304787cb593d0847e1a646e3dd8ad78a4be8cded33710083d83a7b4" },
                { "be", "d7c25d4f72107cf6a9cbf4bfc973d8e6974d17fbd1c868168a0f882e22162f860c84f647e68db210b84be2b5625e44a6b4b64c256ddeb1e6c14030163972258b" },
                { "bg", "39f68c8d198deefd7e86545be44724f87869a3e982a1491df214d6d4359f497bf6dfe6362621d22df3662cf060231798d9e4c13993dabc7c4e21f0167fd53a9a" },
                { "bn", "17f84b686552c2e07dd779696bb88484404dd351b616e598f7b8471f88f83010558ffe4c8f2528df57eaebebc46cd587f18be6e3a1b75805b7c39c16ef6f8dc6" },
                { "br", "91cfd82903818aa970b18f25ceacfce3f0c80ddca6278ded15ba000c28d17e526ec7867f87364570d3b94a08fb80b6e40268b8f5660b0f66f1a56900843d2aae" },
                { "bs", "0b9e239189e930d5929c54fb0604a7945fd3869214d65e6b5429f48a40b7ec661cce0b3b04bb0a14a9f735e67e4065d245d2c8ed656ae9ca443d48774bed8098" },
                { "ca", "a150dcf9111e104c258377246ffb56043ab9f7d8abd13af55b8bdb1f9a8f26fcb3a49884aef66831ecfcc7ca37134a8cbdb73a38a77277d020e09344537b53e1" },
                { "cak", "92122511d0f85d84e56e61e16a32f0ae90fd8d3f2d04de8b4bd9c315bde3b328d686a442de3536f3044e225463525c2f308f1605c2d28700c1e195648efe8c76" },
                { "cs", "2c9dad41e1076c6bea1d3093dfd99e398ca15f7730b3e7a826499c6efc892a643d654bf08d92cef80429aaffcd862e64f0451d1947eecd99b87cf5d53ae2b65d" },
                { "cy", "6b89ccba50b9fa1ce240aec53fc9c2962e813d331b1c53f636d56a8d4eb9b139c0c1458df0fe41bc505b2d1555a1a1ff558d3f1c82460bfe687db69eb8e298ba" },
                { "da", "8a5524b2510c7f18bbb71865406a504950c6bd68abdd9ec77b06a8452ed5cb378b0dfd1971e1ded753504019ed522da4e15afedbe996ac869f6c6b125ec09294" },
                { "de", "7d8ac11009776f9f4786ddec9da28f6c1911ed1103868c8f610965d33001707a1b87e0bced4cf345471e5c3cbefa50e8cfa1211ca35d13e86f2807dd0fe8f298" },
                { "dsb", "ee96be5041b2dd1edc01f6237101c4b00df1220ad70a690d87069a7f0aecd46e5b73093f0790d8db2b13d6146c201735db70a7579529838de88b11e9368b2f7b" },
                { "el", "34baae4462fc5be335c47ad3d1eec67d50d4492d56986afe02632c851660813aaae3925d74abfa70c4839440282e23ab03e220d68b2aac456b5998d02beb5dca" },
                { "en-CA", "353fe1ea4e9de6236cc6945e861fb517bb2823a97ffb5e8db940499f74ba848d4c5f2ec676a59d86c185ed5f4d67f2080a55b11aeec64cb81f94b3966637be7a" },
                { "en-GB", "e40b06a1fb00116fcb5bae483518f6a59fe2ddc51c5ff04f12d7d1b4f64f2f3c0253332f7bbf4e6e5230fb762a984b5f47abc8389dbc6514ec8e92adf7dbfcdf" },
                { "en-US", "c5b8fac78c09ae631380810cf2402a3b2c058d9fd29826fb411b4c3c167e8df2d8216b775a34c336601bd2c8438d2054a683445f785e70d0d3a53f94d48b6a0d" },
                { "eo", "5de98916387425c0ce1737e371a10292566e7e26de893e391df08e1f4ab8e03f31dbd0f6ca6c3ef8b691dcc8d899fd6c3d2e04b9357175e31e88b6f9bb46e663" },
                { "es-AR", "c6cc4a5727f22c2ca95d2687e33203fe15aac0a9cb7e150af70f10cb0895d2b5b7f1b974347ad1dd070f329ea038cd2a488fbf3bbbd0ccbc13b1830674b74cd2" },
                { "es-CL", "e7776d0ab2dc2b88bd068986dd933e87634ab6a5a7467d57e0184a32d0bb3cc31c0e575b011812dd2b81811b7416596beb0338ae8ace0d32ad7a6b5d85442869" },
                { "es-ES", "d7ebd264d85b7f430ba0b070e92ca5e22b610cacea130e0c515ea5b99afb043d3bb1da99f4baf5cd24b8aab9248f5a642276637c20e2dabfa5c053811fa06718" },
                { "es-MX", "00b7f71a21afc88a0595cb5e707b17ee18642a5b9a880220137a3602cebe3ef0cfee2b327112cbc45533749937e2928e6b2695f9953697dc56eb123cb8a661e0" },
                { "et", "5d28360160e2348ac6ea7b73081c93efa5e750d4d1cf8929613436b1a0a70e5191a4c7f91138fa4381fafc3fd5d03e0c686221bbdf1cd54e6e84b51c49b365a1" },
                { "eu", "69391217fadea269e78b09f1b17d9b8ac65e820a337da63ee0f06bac5df36bf41705af9ff7a04a20fe3944d7c6af2890e627216f228dae0ba79dd786e286cf58" },
                { "fa", "9f302ff69b23ede0ae89afcd408a95e03af41b50c9cbbc67edc160cdb14a31534360b3ed89bb2102d57c8039cf169d7e31ebeb75fea56776adaf4a338d12052b" },
                { "ff", "1fccd8e7ab2977bae9ecefe497b4f032bf5d1d607c6d8581efa859934755d97e3dc9b7e835591ba3d688e29df4abe591cd0f087ef357b00c0702e32aa295fafa" },
                { "fi", "fe894b05a259e4eb051068522106a70ff55f11d37aa59b804e215edac06dc138d14ba16a2896c8073c72a287699667235aa2c33d532e6b66b6ecac1710823aa3" },
                { "fr", "164b18aa8151139be718e85cc91b33744f2c11e1d9f8cb9199d85a22fb7afa073fbbc297c5915425d7db84e1ef7099e84052d2eefebe7069d52e2d7ba04e66d6" },
                { "fy-NL", "6a9da59301cab9e8eaf4e35485746602fc576c7ac1b6bc7dc280cd8bc20da0895722049a7e070a3e9101482d4116a7b96d60d5fd0f28cbeccb1276c75906c23c" },
                { "ga-IE", "5940932b967a5bfec1800c999df61e62c00a06aac4466665d492b73f8200571c48cf4dcb41d40e1abce9c989be59be641b5b4104aa3bb2a5f4b5f7e278aea5f4" },
                { "gd", "d4125e73894abea8e3dc97f8eeb3daab56b81156931312ea532aefc57e4254625e0ecec07a8f795f9445fee5ff0a96e44dbde2a3ca0c9735ec5a1ffec03dd27f" },
                { "gl", "335d7f0ad5ef3e8320cd78c5e74b628bef5fe45fd891929eb2300f1c8603e216c009ef29e909dc7b2eed8ca899109602c318b77400a87c26724787c400baf345" },
                { "gn", "63e85eb079cf390a3797ae793b2db1d7ae9ebb4697ba390fccc95150fb7d8843ffb738a2c4fdafa3bad4f7abf28cae04f8f9a595395aac803c42615d3fedefbe" },
                { "gu-IN", "3bf8cc711e6e576ce68b89ff6cbc68c4a8697eeac28f01c0b3b5c5c34690330e502b3b62fc20a86dd304ba71c70138cf39b2957df34be520374fa38a628bd40a" },
                { "he", "64816ff5083d563d37bdbef00a3746be5adb0d5a8980fd7f785185149f5614a136d93b21cb56aa545f69a4fcb77077efa8b51c554d0e4f6a60ee437405fc1f79" },
                { "hi-IN", "4aee56aee83bbffa87f6b28a08d238ae494a3dc88aa31f8e36311daab0694628c6ef1fc70a219528d47220409cb5d38bb3387ac8f47a754c30af0cacf16be268" },
                { "hr", "ca90cfbbb69de00f349c30be48d1eac944faed78417e218a080fb93cd4f37e50e86768dceb97b9a2db025f0d8cdf4593d063aea41057118660e0d7db90b4ed74" },
                { "hsb", "f1892e4de409c9f4f92094829a465d1fc2e67babeda7a690713338c353250cf5918ff3d92e1a7fbc77819346a55f973d60c15c27526e5d7d5dddc1c5165ff101" },
                { "hu", "16d5bc617a2a80cc072e3fb4d1a1eebc5f5c53b13a4716accf4f90256ce683d41df26537034a26b8ac6aefe070c5c37b90065356cc728c1d40f3288b3fd21315" },
                { "hy-AM", "e856e0c28f0327f612a1baf0f473a09b1fb77a047b0812575d5eecf75ae7e2ebf7cf16611f8abb2f31755e9712c2f27e7390bdebc7daec080acee379dbad8ee9" },
                { "ia", "ae849f873f624980109f71666af89c3174c5d91e1088ee562492a9d47bf999e9f38d37e024ab3f259d37ba1b1b19dbe37d7923c24571f1f362adc73ce97c1bea" },
                { "id", "8bed93a9d04881a3f7d4b2d6cd2e07756fe85fa1a78440e6b1eb1b9c6d360c26ba922200f14601127258b54f776b5f710f644e06b4b41aa3b5c1a48ba2ac0247" },
                { "is", "55a1ced63c17e1749b4a1e10a960ed41c7feee441b46be0e416a78cdfd29ae8a116ffc5a5959ffc0d8b719b9d7ffa414489de72e463c7b59de911b3ee3475c86" },
                { "it", "d4dac9769cbde781967d2cb49462eb2b75db04c077bf4138ab141ef4501748ce0beff4e8d2e1237493976c404858a25b9b75bf16a5a3dd669202481b74226aa1" },
                { "ja", "08ca490f6ff1ab5bd3110b9ab085742fa109d8834832ba485a2b3dafb8ef3e7c74f1800cd2a07debbe1d51ae298044e3e67749ef16fac183473ea8a1f35b4ed4" },
                { "ka", "3cb828900b744f75ef2574809734c038a02f2bf01f6838a5c4e65ea0513c723a9902a80908eb2b526e738726f752587575561e55d5e340a70d0a84cd3eebebab" },
                { "kab", "e170934e138306dbe730c1e7f3a0e5b292cb482b243415f8b050c23715bf1f83aa60a05e5b29ad8b6d4e68faf762b46fbc61f0eb85754c65091de2b7e5332a15" },
                { "kk", "b9ce2aa30aadf2b671cba367d43cb606f3903be84d92a2ff870ec9fa8086b9671af8f8d0976525f02a045ef290b8c0e50f6f4ecd7f20cc4778169364a224a99f" },
                { "km", "82619eaa6702105b7fb44a70d5a53c36959c748f9f3a47aa5471956742ec58a437f7492b5a8c1355b8b3939f8b39021789bc5249f1d292e5b60a5e9c84bb55c8" },
                { "kn", "97aaa83bc03dfaee0d146048893201d9250c7c01c19bf923221f568c67d00d470f5fa7c2db8d6d81cc0e2d843d59888f6885f377c9817ffcf13e9fbb20880bb9" },
                { "ko", "d1c1909221f7659e138d5565917a42e30030b9bbd04563015af9388042eb4da1eb3a114bf617dc89f3a4e73898b05b820ab8eab424301c35b58f4c5997046041" },
                { "lij", "d5ebbe933f61a41ad533d6013b873ebd27259fddcf244875891f7db97c71a9ef3ba4118724c842af5bb22ccb667a775257de305200f25c85358708a9d32931fa" },
                { "lt", "614cfe05aac7a664517cd09f9bc58c7713372692eead3ba94df0ff520e01ef904262984f7e3b33ce890a4711d4057225e691d1a67a133784dc90406b252aa841" },
                { "lv", "d25c488bd1580e466790fdd6bd19d8eb47601a0b128a2babdca9090cac0551649ab9c4f154824df7aff09896ced5d72c488c1075f9236a8a3820201092a6845c" },
                { "mk", "7d4c6b9a9c42b5e023686e229083bc1f1dddfb3b316e8fe8b0df592bd16dbd039de3298307fc6511837927ababf09ce3eb122d8065ae90f8390fba20210a5de6" },
                { "mr", "2df777822ff43be191856aa138b0213a8c16de1c5a2e3748ccfbdf3083e6658a8c78a2b44dddb19ce6d5e1717cddcb0397b37c372a87504c3036b3d6c57ea9d7" },
                { "ms", "8b0ba5b4f1959c37656c29c423f51a20c9ff53871452422cc843edc816c4472b7a0b23c21fe6bcb720c2354c20f064f6d0265b9294a0dc70ae38ad45121a3807" },
                { "my", "f8b7a618ba03ea3d21c9041b66dec5962b33f943eda6906f0e6d4ae5f1f563bc98ea8c829332d72aa4ba499b9b104cc5b8d1a3cb6cc5393e8a8aba2d088b59de" },
                { "nb-NO", "30d7a9b29f2766f2a0686b4a77812ffa711395e8a67f650620399cd89e71daabed104881f870bfd8561a688c31433bf47f91dc896d16a9a6815e9f3136380153" },
                { "ne-NP", "f0f0907af978a2e5067edb83c66d14cc10ee4ffd7e64fddab4527b43eb7f24e97989d6338298d4b266a9cc30c836beb4656dc4b6f657a65827e89f35b77c6177" },
                { "nl", "996256a87aa46a82bb7223d8a903c43d10b0f03bfb5857ad5c78e607d9f35f19941e7d6a306585fefdf5f959126c993583e53749e0910a7592ed83abbc753675" },
                { "nn-NO", "390abed88a960eddf262c74c5a839c43a0d5fc106d62b8cbabb8c044e0cd87b21ff93305bed197c7104e50bddf6d61decf22be69ccdf867d3e8f633008c1369d" },
                { "oc", "78b0c149b8c94b094037415a0c02824bd6d1ce4aca2343294d86544a75f53f2349b5d517a8f9d8e9bc5e56d4a8cd04af4734c7b9417fa6ef4f2a07418dbdacc0" },
                { "pa-IN", "a1bdad3b4d73ea352d27cc0cce5abea43acb98adf9b25fb1d97cb09ab51285a3924543a7a94aa56c27d46aa43b7f19cb3b82b79022e01915a5cd97946d65bea3" },
                { "pl", "63d05c7852751188b5484efaf66bd80d3256b03a853c40336af4a49c388c36e12d89e8bea2d07b617952d4b7dbd70452878178f54c43baca51a8956d2160e15b" },
                { "pt-BR", "ad4b0cd3a43f42204ed288ebbb839a4c49649ee9527f20b9a6ec31d9369da13c139f7eb5f2e3d8d81fbaf05a63cc578bb1df3bee9fb756c8a80df7b6bef43d78" },
                { "pt-PT", "56f971e38c3efd9d0d763e44fb06b73bd1ca407f75ad699f8554ba0993639a16855f1a27a96c435ad46305e89f24d23704e6953221779c282cd2c742c4db7eea" },
                { "rm", "328b7797b0eaa0993f4fdc22b914a57b3b27b9aa440ea2d8402e89eefddeb7e6d0bfeaaa4827d0b8df1e15800cdd57d8c3edddaf3caedf6aaea4a7be468aab17" },
                { "ro", "6e427debaf349753d1069dae0f6b8c15214c63a9db1cc7e285afcf323252dbf5751e8194adf75b07e023e4e13799cefa5ed1995da6c9500324bbe994111b86e2" },
                { "ru", "fe191cdfc7fdb072c53580519fd356ea959c48033c9cffbc242243168616725d665c9f845ba169b7e9fa747aba0ce04e7a0113954b0db15bea50b7c996fa6380" },
                { "sco", "0b48c160729c380e2893f07cbf2654f8e28141e81f00aecd63d28c1b5505844815d55a30c8e8379dc53634028a49b2e6eaf858da0d2f1aa66d8ffc6596e5ebd3" },
                { "si", "9742aa9acb0f9c044ea78fd84e539fa6d3955881dd76be84d82c1110c5ea2f32bcf4caaeb2ce13069440402135add8556adab4beebb903e016793cd6b9164d8d" },
                { "sk", "3f6fe733e5302a8d82284ce398fb95e1119dda379645ff1f2da0a890a458344e574e182df8b54e2c3a4e343f5c860285d2811b6e3e06c5113ffca8587fe517a1" },
                { "sl", "eb4597338bbfda461cf5c7ee4c440876d0c84bda5802fedf844deadd2a8fe759a8866d05c5a533843e1eebaf101bc8063a18ed3bd8f2d8ecc8a6a0df722de79d" },
                { "son", "cabcc00016c748a8bded37ed31fedc27a658062c6fab59349089883b2b869d227a7e82e5b8952e34267548b431fd08562120811adbe8cc3fa3150a4506804c22" },
                { "sq", "c30fb4505a5b6a5e035846c048e59e0d11eef75781f056aa3653ffe8458f3135e517e12535ee72e66b296e7c38c7e3de5da08cd38677e903044e1d92ca3d7264" },
                { "sr", "921d42b4619a9d7863152573a9ceda2c45004e57befe9575107f2b082547963936ffbd1cab7ffbe3ea9adb5db6957c5857d138b1dba823e7e41eb30e8a138a0e" },
                { "sv-SE", "cfefd03291beff40e31aa7c421c690cb8fc27315105997b77ac48be628772010299029a739029be324fa7dea6189b8c5ab04b19d6609224b2ab689e560c55f39" },
                { "szl", "82ca0af514f594397ee4009a48feac0a8965a2cb6cd62769c08b8ba5534b4d3884539e6d5d8864b6277f42c9c7ea5abd8c3b3f0969203d2ca4e857d092575226" },
                { "ta", "5d8d37bb1bd680176468421f8e77b693cd3d8e394241a2acdb75f35d71cb901ef91383200988cefdbef948595e4798032c6f71dcdcef962e90eb84c1d78daede" },
                { "te", "bef67fb14e6b988dd904a60e0cbd62b9c8e92789aea46e9317dc2ffdb9bea4da7260fb0c82886180c1fbad4de6f582825a649eaba45e4d4f0614514360a3ec9a" },
                { "th", "02006f5d1ace68deccd249009474c73f580a5d48f59da7f747fbb438d0de24fc8c1a49026db983b62e2db81969514fc91d871bcd4d59cdb67430603b4cb5179f" },
                { "tl", "42a23f34587f8bee166f7158ff65ee78319bda4b1fbda7a6b11cc0edefa5798697f39ce20e23b2142d836c4a3392a3812bbd1357ad304a29053ddbe08ff18a41" },
                { "tr", "e563b0cab58a15a6e3e8f1bf45eb5092bd0b85d403c8c41aa61c644a0b545c06f77eab03a364d98d130a910f62b353a4fc47f2240c2f99efe50bf7c9d45844b2" },
                { "trs", "5889156490974ec911aa386e82d083df80fe6bd8fe888ceb1260671e9c25fbe7e15f0552f0642410184f0e9475e28812f2e8037733b65d4dd74f3a0d3a40f974" },
                { "uk", "81d3110454f32d0d2b7ffa1d04f62eb45e7f12cbedeffc4b109edab455eb364c70cd909658ecab95e5271eaab5d060cce5d5ca3ebb18ed21900908b9029aaef8" },
                { "ur", "fb3094febd5d098e678bab55ad7fcbd845c74df3c80228591215f7a4b5a784836213d4512d1356678972a0b90c979548ef0fe75a6d5da542276b59ea67f35253" },
                { "uz", "6a04c0cbaf3a8a4b3109b568274f7d3cc742f804445a07918c5648889e4a393f5a201141ddac01b1f7f2143e219a341b07420942487fbbb5dd103482047eee50" },
                { "vi", "e3dcfa534187283fb754aa39e04bbaf407c545e2f7a64b8042847b33bd40de0373e6b20a9324fa58d74215a22b88e4e24a27846f675058c08688d693eb2be247" },
                { "xh", "08a30d022cf1adbfc4bc7c56fb72b9c686a732ab7b8743cbaae051d9f2e0cd5828bad40a7c388f753138326178688199ea44f25b31ff80243405612479a9f515" },
                { "zh-CN", "a99edf259b0bbe0b1699beb376a46a995fcefcc9c13704ba96cbd9bb1489e8d82bd3721eb5a68b9b7e3e5ebdc35b5da0dc39f0a1d885f917a32e9024cbe15036" },
                { "zh-TW", "e17fcc611e02b3e66fcb59a3be50d90c9b71bd8af8d3db6fbc5a3a5d0aad32ec678fe1a09e128e66e5da156f6b38291e66bc11205fc45d02645c8921d07fecca" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/91.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "74d7922e45e291b7ad146133b3b6ac23341b153a77350616a2be6ffe74df28dd5f6660b64f35deafcf8bd8ea0c789fdb9f54a33c127f48447cf017b9274185fe" },
                { "af", "a0320517696be26073dc71a837f282a0cf93f112ff17b5739af37b7d968ac884659ef87480349305dff38aa77ae6fc69861494929b74e54ab9ea43f88c9cb6da" },
                { "an", "523a305a98cf1d076e8259029f2d9cdb5bf8b07d5637f66d4019b876bdf2482123f79eedb7d65e19188a338c699cd000400957cf0a764d981afc99598072a5c0" },
                { "ar", "70b5f0576cd011610e8d8eafd53329ff4f428e65c90af816bbb711bcefeec9b2300801b7901351d0eeb6e3c78d423fe70ec1c3cc1c4f723dfb1180cdf8fd7658" },
                { "ast", "d998fc7760e4d91feea34cf59211f8ccdaf299a24d76a6f4cee4d5c6ceb6d3ff349feedc60433d1eb50ad318a391281d13b1733f935529ec637a78f1b3dd399f" },
                { "az", "0b5c3d7454a3b31ceeab8ada8fccbb556c3758943586a3848fa91be6a26ab47ba8c14c2b35a5ed664f912c8203a6a2f9f54090a887264492b4975f964861cf3c" },
                { "be", "1968acd3060ce79b1abd714e484222401fb1fec813e03fe13db3c9b2e2a4260fce2e646884b4130fb69aa171eaad32d1450a2e2e967dc595a59d5ddfe3257ff1" },
                { "bg", "e1c7fd8a5a03a508581647f163b65eb2522ec2207b53714a3e9afb1012d1bec4a9a35f3aa9132921dd67c6d9cfa4753ffae8a9b556cd3adca99adce24c8e620c" },
                { "bn", "c6486bc7c7d315eed593295e8b5f44cf8e075608f7aec1716a3ba19e2fe0bed696c4092853304ce45dbacff797f189ff78494d3af70629ed194077f83546d31f" },
                { "br", "e59425313d2c8738b3a7f2f9457b557b3859f20e7d7a88050f0704ad34d7a7e4a7bef1e41a8762cc423ec770661f5dfce96f8247f88c32dc9fb4466856cc65f4" },
                { "bs", "1441ff9c7e12c021b452c8ddd7fe6276f6a995c6923c4b30ec8bec10c96230383fa56fec6b8ccdf002ff115d901448115ef2e43ec70316f7cca5f06802480a71" },
                { "ca", "b6ebe544a64fa932e379ef0c2ef664b047fe48b91673861b82ae521a3d4c4d7dc9d3e0caf95cbb82b00243349c58942ce6792a698447c238873c4f4813dff958" },
                { "cak", "ea85147560007fa6e959c8717c12ebce940d767baf3ecbf31d75104e8807876cb6d3a96b13bbce90f15627df74e1c208e3219a6e787c4669efebb2adc3f27328" },
                { "cs", "99d8175825f8dc75d0684e00fcd021090ea5001253f764db0946db5976ffa781ca27728e1f2c7f899195435a3909f91250dfc7dfff992c7a8bed3cff5b6c97cb" },
                { "cy", "45397892d654f6cee0c7649f0e2da5f5a004ab0e5f581e89d1626eaf31cbc38065373029cda0f680f69986613509ee468c4c569149f9bd9455ea7d960f66e366" },
                { "da", "4780f9b75b6e4d201fb47b24466d558e3f9cb0302758564ac236c2f9f3b6eaaa703cd544834d785b1ca0f9faa9d4024e97398abaa8ad6b92b8f3efa95cee1f97" },
                { "de", "b415975e51270e4b32910de5ca2dcaf7fb4477433ea8bf284e90999c84140f156fb7f154db483d30cacf4a26c1bc41b9f96f5565b492a27b4448e88cf8fec7c3" },
                { "dsb", "ac27531d6a3098032f20b7635c285e2b165f1b963dccb75a8afd3137652843d8c41a606aea379d81970fe15518f7322d9072627b4e182d4f0c00f2a39c584d59" },
                { "el", "ade6f9ea568a9517556b4271e3ee88a0a6e1897c0def01c7135ea09877ca7309b122ba49fe58ed6293150969c38390baeb895b73ab4ffcb853b9068c0ae49334" },
                { "en-CA", "f461da779e6ec006691537370fe949f69a58e492772825a35dc1d99c14e93bd200b9ecc1b205527307f969c4953426c39ba3391252c2978c0bcc13272767f697" },
                { "en-GB", "1c74bcfe09766881ab493a1f94196569c068f921878107317ea5a5afe52071bbbc1b3d560e1bbce6922586c7c834b24fc122fddd2497b9d75d2db2417e047e25" },
                { "en-US", "aed3d01ad78f778a006a888c7f066f9040e4543e7df9b9eb25bdee30144d39426bd66e67b8c39946fc42f24f75c8edb86e2d63943014c680443f73ec63a473aa" },
                { "eo", "dd6af45d306592acdf965302627b66e0e858b8350bd0d0720441a062bd003a5c9011610ef8a90a657e5b2bad9f167e08a3ff3241cda7053d659d75b0739fef29" },
                { "es-AR", "1cb042f16f52e4e13a7a29081779e328ce70596775d5c6453f40ad2ce62ef9e17fabd3c0ca20f1c46ac3f667931bdf1cfc00ae55e8c7c66821368a0d0b86d7e7" },
                { "es-CL", "9a5e391be85641bb77ddc8cd66618bc6aabab85d8ab27eaea6e2e0628a7ee5979acbf8cf66984f2e2edb9db6587d76a6dd5f92c583e91cd4fc03bca7f222874f" },
                { "es-ES", "9cf5d44def0600a11ddc567c15deefe5ac6280bd8db44bdbb71b9059d588a3fddf870f807a80bc48eec198d10620f9157d9c3092466837f9ecda31d476ac4203" },
                { "es-MX", "43a5dabff8428f23a98207435f83264712e5a8317488749f4fbf4febc6784387d6005233c807829a87c47eaab8ef540bb3949765dc6acfeb2e2b31e02f603183" },
                { "et", "0bb6319f4e538c232f515b0e9134f4f913f9d88f23d415d344399db260d596202dcf78e861612b413b4dc1fc78e627f97986b4ef1e4ac6a361fcb39f9f98dc69" },
                { "eu", "408c96cd3c404e0c004d317e78004b27db937515b367b5112f1acfb4b2a24372dcd21287f3c2d75f1e0e96efdb7d90ce4c5984c5088961fe0ca4a8ac10ba336a" },
                { "fa", "91e82b1ce8145d8d56ea05bb5bedc4fdbbf30b64f192bcdb0b31644d5d8587394b0ba95a20d352e0d2250fd682ceff4d3851f1f8f13a099a5c8f3610f3b25a53" },
                { "ff", "f6bc173d7f9bec2652f01305aa4b9ddcca5690fe3eca819691084d3e4726d6245454617d30759c163d13c83eafe16507c78c1fb0aa951847210318c38e899bd1" },
                { "fi", "efde8cc7b189f4ef073a148ab78d5afdec78e126e065da4fb25c1d0dfdd2fb67e36d9e355de61519dd52073348d2657ace30abb0242cc9ca006ec96da5b2c65d" },
                { "fr", "925951fb5b7d75b4e115da766122e618ef94a864a899bae53a1fc5213ea226f13a84505ebb2091ce31bf941eeb4caf0896ec27725d56a6b11a17190e6e8c8b44" },
                { "fy-NL", "2e407d583ce419612b190f90136f116f1b9f68017a5674e5e78feb226e28520ba0b8b0fb55e1c56d2bda7ef17c45075f6ec4fb68d9b0bc38613a5ff007d95efb" },
                { "ga-IE", "67d184daee655c7002e84d66100be36fdb7b5d94d6724b608618258c5ecd403e3f954a1cf5f16435105737d22387f1fbb6bd24bf7eb86ee87f5eca2f0f591806" },
                { "gd", "d6c80a47006580c4226f4efb1e4ae3cf7caee0c82772c483cf2e1a8c1bea8223f71507df55e5a365f6151993bf1a4fb758f7836ded54cc2d74fd90efe17264f8" },
                { "gl", "819a47346c57a5c6342afeeb38a6d72e1d469f0d0a1fd8039de8f81f5347cdcf48cba436dc1c4f51cb24a9c2aba51e053e02bcb2a9ebdd017a3c9757ab2d5f81" },
                { "gn", "714db42d2e455ad83cd1739a03e8b87ee6c41ff0cba4af38eb2291507bb4d31e09f156be4b334e53696839b1e7598936ac84665a2b6d3d68896ff0178b6765ee" },
                { "gu-IN", "09663285a9b7556e50c80e6c86260a471746590629aa87bd555245e4a0fc5209f571d7da29d1806991b458b7bf71d6bf17fecea07db9700f7ac21f3b72855817" },
                { "he", "3bad588454e447727ae6120190e9f3b6697cb2540673b76fba8c4d108e64686aaa43c3d21e59a1f737d79517187bb3aa56a9973ecef022ae81d2fc0680fc20ee" },
                { "hi-IN", "99f68fc30cfdfa0190798c08924414203e5c5327856871e2632f94a85f36b32d2d5b6beaa85534f205be602913e37ed88acc07e558810f69668ea43e8aa549bd" },
                { "hr", "a5f0714d75602a55de2316fec6c46c8a4caf240d33f85e87a3b0ce3985d0deedd50519849fdf3f590f3db5c6840f7266edd42bd674f3d7b076cabba4570ced00" },
                { "hsb", "fd699bdf8df63438411f234b4c8361ce120f7b58fda8e6b5badb69f7a005b961aca574fcb7b721d0188e2178f4568df74d1f941b279d0e2ac824e0206f611d97" },
                { "hu", "cc8a1b833d2702301c056cdb9116c40a9ad71256c3f9d42b461458a5bfd723b2568ffe064c3572c0d99b7ac5de5f921b721e3a4f7bd393ca71e0f909b5a9d0ab" },
                { "hy-AM", "9adce06690a5ca4e7d9acbffb556c52e99c1f4d252a3fb205e42ddfa19244134afa90008149ffc3aadfb93980deef16e2f966f0fc3f77c5a6bd6205dd5834cb6" },
                { "ia", "261690de810aaf3a1e2e9b292fb78a43c08df5e324d14ed873d677b981d7d6c3d356878da2eecf3794070608ef7394639e28db3e2dfe39a7f1f5d7b9f20657cf" },
                { "id", "96766c4798764ff50dc710b53d5e39895dc9c71dc6730bde6a0fbf8e19a5d6fadc64bea3f3d9577f2a20d16fd9ef0cd84799a3b5918e17932952c9868ee52598" },
                { "is", "61e5e482a4ca12640b5f95b41548bab8f3d83eb76e615a67c18836f07745fff9714cbbd57285ed0be6ae3d95961b0d997085cba5b64af9d578918e69945e4ae5" },
                { "it", "9ee4a36e77f5606b61a9741f407bc6a5c578a3a865e0a1a79d6addf116c7a0be521a76bc3257642755470c005b31547ee2d373bfa14ab4d171802f5a6d81b0d2" },
                { "ja", "3b81844190030b2e26e9362b5dfeacc03ff213e41df6f95ca1c30a924a0cf3fd5abcabcb94d3ac4f1266eaffb2a07a4f9a47a1726c847aa96efe4d58084cba2c" },
                { "ka", "231533687f79d8fa402f8af7db70ae34079680dd537b195c74df7ebdd195f7d42d657a9eb7326be91761ad761ef1494b058dc441c083ebd24772bd40ef272a6f" },
                { "kab", "0c175b4ef09d37e7bd68009066735b493651a5cecd56eb3851c148ee7e4aab9e13cf9ddbfe874f7ca947bcfb181e9c878d17a7c1fefe7d8df67726c5bbe48b83" },
                { "kk", "248988688da30ad2bddfbc585016fddf70d55d03fd2a6031aa57898a3d6beccda083a69834b9ab12b4d84f47349913276ca710926b99307ac021e938e98bf897" },
                { "km", "984d236e93a1b79a28daeb23fbc8d45b43f89bc2f6aee055e78df20e51eae59f44b48a684b6510722858adfbba6fefbbebe8e9e5e8b611967f853d26c3032fa0" },
                { "kn", "6425d774a6af67d748570b836af165095da2a04a431d1266b58057bb5fb5fc91283e467ef07a55cf0bcedb6a5f77f85f92302ae700cb4dbe1e52165b43ff9d7a" },
                { "ko", "87d4a77df205d552f65d79dd499c7487d86fb332089102a38823f20543620f6394c354d4a3bac859745e460431b78c9cbc0022f33982915739ea2d822975d435" },
                { "lij", "d040cb2d2a5e49d056d00d0b7fe1e009aa96f19392ed719dbe757a93283262833ed502201eb743c13c9df39390c4798450d565ba38a4aa02e0357bc5ac2bce96" },
                { "lt", "67047566c3fbee1e49a7e4086c3747714f17bc8ab1abb490ab8060d2dbb445d0519ab5eafb8fb8b8a080db5dc4b5730cbc1a9b98024c8dacda15bad7521512c1" },
                { "lv", "12b8af86c8e1e7481f0e921047f404ca7dfb051164fb84f7930e0165c05e152b6b50b2a497b13f2eefc80346384078a6a9b3cdff27de26eee2818e47c104489e" },
                { "mk", "7c66c207ef8bb7f782e8dfc55e876aee423229e3646bbb9fbe0d04ed68e16cbaac216720c472eb0e59ed3697acc94d64c3a57e05579506170c3a76cacce0eb54" },
                { "mr", "3b2266d37b8a36b677c5bbfb95b5008290d11be7512eeecc2a642e6690268470e1970f460a043fa30ff7de4126b54b0dfc94017fc546daeb8bfa9ae04d63fb0f" },
                { "ms", "8e05e3a7deca2700e76577237d7ab6b2b8e631b612eb2ab63cc8b5e4059c87080b6f5d3d2e1b9f3385a1bc6e84b9a72493eca091ee8a02761c9fa05811823cfd" },
                { "my", "b200c64a8f3438544bdfd771ffda65ebff464144add58037e5866b39fe630a8f961f404f13f595055bb0f858be4a49a5ce8a675c7ff9ae45e8da60f050aa3b23" },
                { "nb-NO", "35126c3faa8c45dd9c0bb6680d4611b10c3ae5a079f4fcdb0ab8172208aeaf6cf39086a2947538640fc8ed5c908c6c5607a6eeae44ffdaa9136c7f387beda324" },
                { "ne-NP", "21cbae2dbf65020c9f302b66346c4d74a512218c1b8d82546559097d2f01f79e601760f593d0a9068adf52e6583d1c3e7b626c48d708fc7985f94be256169d6e" },
                { "nl", "6f0bdc02c66f72d2a6d0e59fad3d8fc79187521b6c581c8a14dc416048a2f238145471ec02f5a7819180bdd587f61ad834065f9c68423038f3fcb1d1da554927" },
                { "nn-NO", "5c9904a4829c91f8354eb2e8442158df5bc4af2fa98cb3dd22b79d7d824d8c20d1bea01f35af0b2eb2a16ffad97a24fca3b471e77f6f94fadf57cbe85eb75b21" },
                { "oc", "e61db14709a98f24df6256dc93884a2ecf10fd5f1e5dfa66f9f16df2fbdbd47a2381ef318534fab941871d3434470adddc8d2a34a6eca06b5a0e0ee50538c48f" },
                { "pa-IN", "6eeceb7fef6a8083fed9afadaff5955f772abe350f984dab2a011c77b9e6f244921341c47b707d5c3efde3a83943e1b269b0dbc0cad10bdf0142bf17d543745c" },
                { "pl", "5eaa745f5ffa3ba0ca4740b9da6c827bb829911283f8decee4aadeb1196ec62fab9399fb57848ffd2c87f39e800f4353d620b78af4369d028d4f6881e3482de7" },
                { "pt-BR", "5ba4d128e1d2bc0e3638baea72dd7a2b77d32c4b6b27fe7eb45ac3b5875e9aaf658285687fc10b7df69a04ddae44b9d37711c6fef74ae108b99ea4551181f838" },
                { "pt-PT", "c3fc6a2b3c8ad06e420600cfc3686ef4c643f352e6232702cccc31ad8ee0f8de2e9bcd0ee2317203cb2b6f005c10b006d75f056aeef6d66d7a4aff5113f6b3b4" },
                { "rm", "ba39d8ca023544c1f059dc6d028937e36f62ddff22bd8c36dd976ca754b74724f7ecccde1599c733898e2d855bd98feaec4fe7714bd80886dd3aa62a176663a8" },
                { "ro", "7276eb5bb8385b3a43539ecbf36f39f8bd5a8c38635121e352479d3f7a3ae01e296def21c5807ad39b54684b3efa686b62e5d04e62e2cb05a33ae8ab65698b02" },
                { "ru", "2605d65dbf32af848840324cdb72c1f299fb32b9bb2b2839cfd6ab0e3011437e8ca341e159e89a9ac20e24dea7023ff497eecad68da0b0cfc373badb22882fc5" },
                { "sco", "86ba5db4a595bb1b710ba20b64164c97dcc0ec7bd260970741ac3653534bdba0b7c91fcc05f749f7973603d88fef9a6d57b3f2e346bcf0eeef0b9023b80424f6" },
                { "si", "b63dd074d4a826a13890eeb45f983208d8223a69c4a573daa3b844d155f52cf7cc7cbafd3964265f7029d52f27a224a892ddfca47aadc1e6222e19235369baf5" },
                { "sk", "6d948e6e28ff6941b60444766d8831d82b00946595d827a6565b0fe2b3a276ab25056a36a212f68481d6544e3c470f44d31cae8821f0905b609191e9094d93b3" },
                { "sl", "8a63825f338ed4a0452c1d27bbc099eb32e46f0893d8854dab5a131283f0a440bdb04d62585571972405b366303885be76d6593b6b62e36361a26b2b2120a028" },
                { "son", "c5667f91742d9b00e7be054724a77a4fa69af7f3bcd8fa3c156ba794ce93c1ba424cd8415d2483c5a265e9d408f67dbef75e0999b5da28c22972be316b0c8483" },
                { "sq", "d849ae0e2eadbbd1c2a8335105e21229dc9fd10dbffac9dab81b36da3eb3cc8644172905aeaa19dbd9cd78bb89a6d1265a30c18913cea956162fc38bb192da5f" },
                { "sr", "b35d562598449f289369991a5f028b21a571b078888ff11a450f2ebe857639fab8d72a5030156d8e3b8ba27491b84b377b8f8f784bf87816b9a49f0009da6745" },
                { "sv-SE", "67fb617129ddaf76d0f89e5c1a5c2dfcc7c44649510fe93adec35a92db9d35667c385a32cbd4042f98739ed88e1efd51ee8e67839393105ff266a8502d06212c" },
                { "szl", "86c591af3a92adc5eadd3dbe447800ecd7afc2e193a3110ee7bb09f50d60940047f66fc729ae00510a4f4830f87491e4698c845e79078fefaf21df0297e10a07" },
                { "ta", "f25dde66098a6a424bdc980494f3ee12e3480e7e7f75bf8fa1d3c010a589f289f327e6791379f308a7c3b8ac7db6dd4c3ac5ea5e504409fbba33b13c8a95e576" },
                { "te", "efa8deafb9a5fdfcbf6d2e83caa4260f7715c9d16ffa4977065a89819e4c5616d04226b77ec97800c75c00cd2d808a765727f7f3a2a262e3594b5350546456ef" },
                { "th", "3850ad7bbe2405dcb89b21706ef6fbcd74b9b585ddcaa7d9b4f87a142cbf1aede7e8fd7e52a6737651eb8a82613750cdd35dc76bd8cd26a45998d1c561bbd3b8" },
                { "tl", "9e5ed968acefe3f6a1432cef5953e352326e9f879aa64cf0f4ee8345f1a60ca6d594fe3aa28c534ce6f682b211b02e97634b06910cc729334faa6f9179b6e663" },
                { "tr", "1446bdf5a2449dc5a52d7d2e0f024fd07a9a8ade242a49d055b150d1c581e7e8bf3435108fa8e0054666eb51767be14bbd7ca2041701ee31a1c0ad3026df3d94" },
                { "trs", "02308cc04b77eda120241c59013110e5da8b3b86b4ee7336feb7910a41269e68f58313dc5a03ecc18901a03bc6002e8fc84d35039348f03bde7bf83c0beb83e0" },
                { "uk", "4c3b08ddd7cdfce1924cc38726e002726dbd2b897a15ee70d278ac13330320ed45d9ad31ea7e51d04ffa563857ab8915c2e270500a62e06d5a200a890f13f7f8" },
                { "ur", "408c51adf39f994c5b86b333426982798b316c93a8eea0c798dc2de2e76b0f21a4bf00bd652f195e6f28e96f5a825277fbf5d145b151ac236012deb1e56e785d" },
                { "uz", "93aa7bc6ca9b629dbeffb1b07917ffb3cf5afa94b1fa586c9bf2e95931744795b969089f148e43b1dc02344ea4c214fcd5f1fae736ed30bf0ca9fea879948d7e" },
                { "vi", "5b40b865f24dc13ce087ab4d0fd45bc76c0b520cbb45a886fb5ccc1bf52d82fcb723291b88f50c57849649ee26b0d2bf6eb0a224c08e76e2625b1ba9ed59bb07" },
                { "xh", "4eccfaa06d5a0e54a186e6720785620f9f7874066b360fd10018f38eafaae21767b50b21b3c47bf19f2e7f602d54207f116ece7bd6b306d7bd629d6b6f5218b6" },
                { "zh-CN", "ae0dbbfd92bd4723bc3b01d734e7bedca2e8385c735d49f250bb4d5ffb0df495f6d8043ebb4e27272f01b14d22326b01188abc09cac6dd49a983ea59ef74a2b8" },
                { "zh-TW", "7fdace708aea2494060fbe1fb2286725ba1843b9154aadaf44a0bdd8d86d2019a39522af9b843e76aa526e01ca9714c0b4ab33473d803c65cfd797f44f709251" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace

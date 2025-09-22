/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "144.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "aa23010fcde5c8fead4696e883e9d81f214243cf57b3df01f77477cbddc3e848be5a3a5ceafea05dd09c7780cc323a83adecf08b8dadb5a61374deb793e09f97" },
                { "af", "591b507215ea949079043d6ebf8f5f0b6fd306318e72e603c7f659b341c358862e46111150e439c6041b96bd1e6ccfa4b434b86cd6a8655e989d856e76f6b0db" },
                { "an", "6abf3fec6fef6f6830501e571c2c9789839999e81c2b0caca6832e2e0374490cac1a7118e464d0912fcfba8da74ff727bc7029a451da379759ee8cef464043cb" },
                { "ar", "02e19354d4f20960ff334dbb5d25146778321678b59e0af443cf77591512caff0b8efbe8587905569bbad18c34889353783afb4f6445446e936816c8c46595ab" },
                { "ast", "382f8baf1e36a91d2b463a0e9ffffe3cbc7d2327924d574981e72a7d8f780d79381eaee9f8f3e9c56394da825621b48d81d0197a799cb92b0913c43abe82b208" },
                { "az", "54dfca9144333d257b59e445dcb3fc782b66db735afb1b8d1aa40983afcc335ac7b8164312771cab1c91f7655f8afdfbc030130561dba445f74180aa64ad2b8c" },
                { "be", "34494d0e580819100797b1ab5ef8e9d35900b3ec599a6bfc578fd7970404bdeb828830f68e9ae155e14eb865f85f92d89338f5ca100232a838b2d48ef85c5fce" },
                { "bg", "bfaaa7b8888f631472982cc465ecff81e325d8bd6164a9312a69215202090bc2eaa29ff1845288698225caa73246c950fe3463b62363541afd87add296c0b3e3" },
                { "bn", "60c3a2bdb9d0bf8468cc36e39dc49e54ed6e60efdc6ea44059984f39dcdebb26eb43ac33e2970d776e48e2c09fbaf9c7473796a6fdb2e2208e44ee60d8f723ee" },
                { "br", "44b4b8e13816c4c72e848d426302b18731937a1deaabdea1b64924315f4128867182f967e490efcfd2824e1b2efc313874a60ac20d0e2924cf6826676e06cb89" },
                { "bs", "d94410ef18ec9000a7584526afa6611ceb111276f2b4f57108493ad0fb2e81ccf68022c3d7273af1dd2f3618c03b6b755da77ee5774ec6f59fdd0a511e1f7600" },
                { "ca", "e57163961212f01e94d794c575ed19bef59f66346c251e321840a90e11b5184dce03141a789cd7bbf936bdfd658b3fa0238cacb7d2ef423f723af16d0481eba8" },
                { "cak", "d8a32cfa1cc778cf1f12643fb03b2f6f60721fd306029ae3579629250971142493a38533c9035beb59de37885d7e2e5a85a1ba8b4fdacadf5d22938cdd73e1b7" },
                { "cs", "cbe68b02478986e608e81625326102880050df5c6384aa79cb00ebb4f07a0331309145a74512698d3ac82d6ef7c73048a5700ffe691a3156f3e1c8ccab10c009" },
                { "cy", "6ad855d0fee1b431b74c555b035fd5fb8a320863821fc746fb656c7be93749b907b0df22eacb7a60d900a4ff9c45d18360a398f983a392bcfd7537cacb4b242c" },
                { "da", "4a27f28ee14c472ff3a211b05cd9319ec09c0be26acbec883982a4abfaf8228629fd303404b4ad911bc7bb5609d9f435df867b95360620e6076637159cf95e6c" },
                { "de", "3a0688b25f49d21755e7f43359a92de19edae3ded566d218188d75b713996c5c79ddfd159f2a202967a96439b45ffb0155b78ae9fd7971d3840b08213303d267" },
                { "dsb", "d210a243518730df2a7e8349c4de9bb922a815cd0d26e9423206dbebeb56c062d3b8b8946419149bceb53a2eea1740a75c0f40ee7d6315a967352ff2efb663e0" },
                { "el", "5cd6770c0d0e7b3eecb53e49c2951558957f38631083ee844f301370cf1e0dcb8676415c360466523d4be7e12683933c02ba5550a30bf45928905953de56292f" },
                { "en-CA", "7dfbc933670eeab30b12cd41e06ef7782660b5335ea4cbbfa8f27b9e670c4f4fa38d5dad14665ed28d7254e89e69fbb1c1248386a981a1939c9aae31e68d4488" },
                { "en-GB", "0cc63dcc10f596a978d7f0438fe50adfd53b15286ff48e3becf881c4e3ed966cd96038c7a75e535c60cb66ed251829544dee354bd96443a3ab0a13714769b9c0" },
                { "en-US", "4fc186601fa035925381de95394df162c41e351980a454333d41c6cf88dbc48f480c0ca3720459fed799bf2a5d4a13a51e81049604e0d45bc63f645b866b8638" },
                { "eo", "5c2f44df5c5a0395c64a59ee6833bafecf6010611bd19de4ffdb423e387ffcfab24223b3ebfe259f6bc4ac0845f0450de1fc6a1527872fed699ff24065aecd96" },
                { "es-AR", "72d96f0711b93b93fb86112687660c8c709d578cbd823f6465841c55e4e1bb1d2b2c86f965ad3adb0060f15eb4a2d03e09f7ceca93caa30b5d6f6f55f2729e0c" },
                { "es-CL", "d9809eda5663e657af9e35ae907c4169158dc37802520bf712ed9928522f150b345d78d16d4647656739b6331908c76d7e82b5fd5dd17e395390663bc86c7898" },
                { "es-ES", "81a16f71baf2e2fa6fb6fc592d5c4aab0eace30dad2d7e469672e26636ec860caec56d97f78bc24dd2bba0c98fc8cb803bb4676c962f93927aeb23762ba73463" },
                { "es-MX", "2b6d2f0647eb093592a437f0d01f14b2397359d5750b881e42540c5512b565917d4b8687890ebb1f9739763ac873dacaf5840cb0fcaa4ff0bd80d578ad03b11a" },
                { "et", "cf2372ff3e06c0b61195e0fcc5dcc242328ef439536c42a5da5a034eb469ac25ffe66d232d84c049ec5b4a661c15a357781255202367dfe4ba9c3c91fb44aef6" },
                { "eu", "6baea1425a2f4ebfe224c775f38522f310cb6cc48c04258cb9a9aa3f16eeb5a1176eec12d1d8bd3e342d6493f9c1f74e2b86839f4ecdb8691b3535dcaa52d72e" },
                { "fa", "e99054059ad4c62faee95b76cca592854b50db0539d05b4b730f47b95305827324e5292a372636e2598c5c1d7ef6070eb1a1cc4f1922d320362eb9d3349d0a06" },
                { "ff", "fdd12475a99d1e859cdd38ad2f1ac9fd382934e4762529d3cbe8e52c432f9af8150291d26e110ddabf3b0b314d0bdaa0859a998ec2ba96a72f47027437da2da3" },
                { "fi", "17d2c94fe0904b83478d2da466f774e6ca8f52079cc2cb1d40c993823fded912210670cc315a19381d1600dc710cbfed884110330beb62299cfa08e8edea07f2" },
                { "fr", "2dd07a727cfc89f83a1e3b9798fa7b7b45df0f3fb488ea86bf0fd21ec39058a8a1dd2546dccb432ab44c424b406cdcb41639eb181b36f4906a5d45b8c1f1c16c" },
                { "fur", "1d1ceea6cfe3170208d9364513926df0c74991b3d5e5ace0e3c767bce761cc82ebadf005eaba82d7180fc0749ed0270d24ef1624840f154bd9a017be08881b7e" },
                { "fy-NL", "b94d9c67e996e0e9cacd84410ad14de0b6d631efb25c86c3190f9339b70836553f576ec21ee6b6a74e74e020e90ed3acad776f3336977b590fb5873a00965c50" },
                { "ga-IE", "d92ad4d55e979f7cf4822d2bfc72180adf61a3cfddca5f9010de9b1afa27ffd220d59417f9f7f5b2018cc8d113c3764983a069c5d7d3e8aeffb1a7e0f2071a36" },
                { "gd", "78904c23243c8bd0e27951a11f9221be3785cfb77972d93d727566eb5599da220048de052ff1431a3dd110b4f6016fe3aa9917cfed2ba55b4d85f01a98a8dac4" },
                { "gl", "4f147a3a219e9caf9378840773c341dc5e040ae5430833a392f143fdb35a6f20ccfda8ec09b3170c2441c56790e7442efc1df6044573a8e4f0ebd9274d3fbafe" },
                { "gn", "66f5d84fbeb58e5343bb889cb45b1315b99fb7fafaddc0d6c79b1b2b660aec769c7af8eace5db334ca131576e0eeaf7aaff84a1bd75ffe76f6d55914e3807d73" },
                { "gu-IN", "2d61a694e0ea8af1341650f745e8ea45e4123344371dca451e1a495f608ed1e315c0bc132cdb344581bdacaee2cb4cd65b111973196392e0ecd4330ced1db8b1" },
                { "he", "be0a3a97fb2a109e13fb21367b3a45ebbb38834d8765f13b5b85018d443ad0dc1cddc610154f2d20dc980e862e7f9c71dc19553aa143559f3763a1b250d95616" },
                { "hi-IN", "953ac43a4606ee73b09eaaac9230b1e964bf9c1a23bc28f94de48cb43fbedef0de59c86827add332da633a68bfb61c5fb8e9a31f0ea1c0b0433e651e010e917b" },
                { "hr", "2b92fdcd0665f34c9eac107774c53b34355dab00cef627e6770db84b004650308e22e2a292f441b445d479132e2ae41b472d5fbe7eca95c4ba299cb65e6dbb88" },
                { "hsb", "664fffe95e186a01a2be29e27c0304bc48d25484c133f6f2d4cfa1c349ea3f9bbc2979729e1adbc48732a264d2e624ce14df7dcac2a492b68c2411557886cf7d" },
                { "hu", "37a62796a5a351863834bf4ef26ab6202da07e741252d423781ab313f575974f70411f5978e0fb2a607013f395bf89db3205ec363dd2de455c42cc8d2520f204" },
                { "hy-AM", "7c3773ef964b446ce673b63db131ce02596f61ae736524ad5999951e417665be00bba997620a8d43a2d40bfb364dc3bf70e25fd0a800430f52ac8ab0009e487a" },
                { "ia", "3e243f6222d32c3cf809fd1c47832d872828f128fb5948755a88b4aaaf64b09d05f3155f1a591b39b62b0fcc6745c814b44215297afb9c1a25ec894bae20199e" },
                { "id", "0cfb57bbd1394a764dd18fbc7062b1c179d42f5b16ae4921fd9a5cd9175f6664ea7069dce5b9358a2997acede7b8106b909091c6d6303639278f8a14993987fd" },
                { "is", "e6aa551652b51c22d1fd7f1f92a557f22032749488f8d73d9deaa9bfa7f0466166f6421c27dc001384906324db7a0ba7d3a7a9e473945dca57552c6364390ba0" },
                { "it", "7dc8d1edc45917b3987e8bea762fa7b89163de3f21e161952494a13784daf8674703e0ed8a351d2a809cddbc5e38af315d3cff54ca0164085ca28a27a1720ab3" },
                { "ja", "bf70ab2e9e1f5c16d297ce53a1cfef3926b1e1fe93165a7c6e6b4caf56ff7db1e092bdd05be625222a7fe7c3751159d699981c869a4a216e8ce26959b86cac85" },
                { "ka", "6d6f16032ab302ba476ea9e9ddd7df0647ac7650237888aceaa528d90364ec49286ea3e75b0da6777a909f29b1b3c668255b1487b363b45b114f2eda0ab5dc89" },
                { "kab", "be88aa5a31562a85b6e00b7adaf7d0037cfbae1e5f3b21aa6744899e5fce7ffb24c26107c07e3c4821c3fce7109dd2444afb352351cc17e2f6cc8d9f14a61f13" },
                { "kk", "ace1c7f00494718034e051f93ded1284820187a1ab720d13c0d3d47e72ef67939daf7925f8bbac4c3180f57b9f2bbaf675439320131f6fe31ef6e37e774a8b53" },
                { "km", "67604a0c6a2a6b4e094dfc5f0d2971c6bf4e9fe54c901973b7e73e58ee8a745f956cb0e9d059d75078364b78a8a27699d1de27e4529bee580fcc747f60ace0ea" },
                { "kn", "add688750b0a90cec6e8c4350fbf64ce75e2045c11589001afac6799a77fafdfea803ebc829fbee26440dabbda957948a2e852605b31d65c6601f6bb447cd621" },
                { "ko", "94b4792e6a0cf5f2eaaded557a50b53a5b209f2719bbc1d9b3ad90cb7b4fc428b05ebeb428b7852243aeb067a7a0fa76c8c854963cf0f1c473d6d7d4d04d9c97" },
                { "lij", "e1891003365672e3b9c14fd5c084666c81cb4b52f7788bd545d0be808bc055d9cf853f673e8c69bd05432d0429d6fab245ff27cef34c9d972d177f23668c3397" },
                { "lt", "268425fb1c98acde4c970059fae32afaa2bacae79cd3152f19fe0df8d0a24ccc45ed8227bdaa30f1e4764960b1d04f5213fea9688acb2fd8f3207ffff218beec" },
                { "lv", "0323b26ee918495ce2959b1e92ef980dfff92d4a9ae982495688a6c154af2d79d9e708ece4c6ee6e7ba0565f48f8468a593915625b1d4f97d99e1aae64a2661c" },
                { "mk", "d7cdf0cee6604509c0557eea15f7ac8825401f60a71967504cb560cb45ca7a782cebabaf8f0d98b42d4a259e0f6008cc19e99241ef736bfe7c677ca77eb45fb2" },
                { "mr", "bac66a11bfbd5280605f5a0e8a2c8a080d54c86712a00df607b2b6924827ae4aa5c99512f339b07068712b3c93b8257b5f940bff93f76d6a57eaf74c53ed3984" },
                { "ms", "a0e7c36337b0214120971f4cf9e18a9ca1d7d7e92dfd566642f596ae6f438e20d32224c69668d911fcc353a51ea7db0602d059081d053afc52973232420b4af9" },
                { "my", "184d57ebe3ac849d8d2850acdb7f6abab5732c997bb928a7b2c9ed2b781b022cfaf1ab1158a480aac5a3d9c5cb33b4ab87a38d45e88070666d881a5e58a87b20" },
                { "nb-NO", "170d37d2a1498ccb322a45c862d825dc9d8366e6209313a142124cd3da7a100c2031ce2295ec32cba3eabad797ade61f0177127222487d400bac1f0638e7c692" },
                { "ne-NP", "d78c3a4ab540c03506690da9352f17ce635e5fdfa69924ab31ed5fc74221f116cf08bc277109edd028b964e21910a466a4d4de29b974912d1f86c5310ecb3a85" },
                { "nl", "d488ede7ef6e7d4169bd48f8c0ee14d7348cd8a8779aeb10385abfb0c6c0c88346a83ee3b49860cf2e1132250f172fc786068f04cd8c9c472005e16c20e48215" },
                { "nn-NO", "a6b6161a09593ebc2fe94f0eabb5f9a5cb080229a530c7980da46ab02b4df0bb3f989b4bfd09d3b99b79da5f0dd33a710c5c6130e6e656f236f384a3189269aa" },
                { "oc", "51ad6381ce825e9e5cdf431b1e7d321039f2f5b3b74114fa3da6afaeb6e966413aebce32437ed0f43c107fa6f97dbb8075771f4173d14841fd131f98f2703d6f" },
                { "pa-IN", "e0e48d6c4adf661bf6f5fb4d273e4775b47763dd39df4221ab1c413d3f22301c82e4acaa0c34974af50c5b7f67e33daf3650df0f44732c102ced37a489ee631c" },
                { "pl", "ded9279863fc4d445679518344d399dcb9953e3169827f88068a03d3f5df365a3fbabbcc1089a35de066955b8d21e9e47726efd1af824cb860424d9f80a93ded" },
                { "pt-BR", "95527f6bab562c39d1583bd75d19054c144043241b748a9f73f119bddc7cb6faff23847ba1b7db37d79b3e8e826d1325a0cf4a348ab8a17f1b41fae4c9f8aa80" },
                { "pt-PT", "0f788dac57ada995ad911bf3e4be2f1160c4d9503ff4c5aa2d97eefff00b9af3ec30451fb97a219058096c5e10aae560a036a9a8c01194937408a9bd1ab61659" },
                { "rm", "6870ea137ffb766d569936668ebf1daacc6252d6ee37e50c8bbb0277f47acc9ca368cf1c3ef285d832a7981bdb9fa89a696768aeaa43a4b6423851502bce6e91" },
                { "ro", "56a70e1fb356d6154cfd9dfaddec829775bc0bf931ce9388795c4865bcb9d3f84fc0eacf68d504859bff31d08df8911fc7f238eb65158f670941abff0c827b05" },
                { "ru", "164b6fff1afbf96bfc8e7d424ec8b2b3c34048bda045abc16e27161ccc4b8a185d39bb02754a93a487a5f7acdaf34c7aad8dd35ca7a57a270e4b61c7355d38aa" },
                { "sat", "4ab92112c817cb8e6ab62fcce4695d2b1e96e68a5212e4566a508396f9e33441d7ba25d75b733a3c8550767e0ce083e2a1b693482d151d9b9e93447fa0eda665" },
                { "sc", "2dc60de9ad91040b3b3f96329a07a549c4f3407cdc5affd4bf2b67038c06fa4943b94f4fb96a83f0f384c0acc9b6605b5f894dfa102f65949ca9fef88e0ed6ef" },
                { "sco", "8917a3ee96c778abb9d227ee07eb2432086a2eefa16759cd7f30f6a6c996904289a9def5d721c95162f4227604a6c26967dbd29400aeb95f6ec071bd1ac16e5b" },
                { "si", "9a672c075f6ecf3f59103cf3ea36da5e1e45370355450986ea5429f0dd92092e82dbc81cc7ed43e7f915c33757e9eb8421da5e61ff881e8b15c7a8a028bb738e" },
                { "sk", "2849694d9f681b93e03280c79dfb33c1d404c22cf716d79118a99597ecebfb7f693e357eade637ef43817daafa0b0fab1df917ec4e58339c751ef0d7a247ed04" },
                { "skr", "764c96ff4dba558239c25951b4bb58ed04c084fa22d7b8d706c1d629bc07d92722d4195a53ce9b3a8440093f2da1dbd3f279a2923ab2a11ff053fb13aac96f6e" },
                { "sl", "7d815a232272b756ffd9c76d633a2ed26ca7e3522e180a1135ae753df9b85321f2bd03488d3014e5f0ff30ec7064522e44e2b5245f2b992672cd070f869b7e04" },
                { "son", "970b8e52267783bae9f6eb2909f116405a462220b67321cf0f39839ffbaa9c4a5893bc1b52d23d12761fc0f576a641b10726f86ea06dc978765c0e7ee7c26a18" },
                { "sq", "4f196f318877554a15afe8febcf5c732f2840b8f7a7cee409b70ade2689d5534ab13cf5f9288a92076cad20a685b9b57e8fb4e6bda31975cb7eb1aa5b6d34a64" },
                { "sr", "d0b9f632a7d22b24cce65622958fde430be2708c9534164362f94fcf24f6f3f52e1b04625376f8628aff990c97ab0fabe0cc6a458df317c19379cdd6d1a30326" },
                { "sv-SE", "7d6074f7ec419c6372c5b94cbe79af5641ebb8ff22248351edfbbb0dee0cdec13030e9104e66108a35b56d07cd76839cd24dee6fdb9db01e24a26aa8dcbcaf9b" },
                { "szl", "3921a899d67346d7be2ded202344d63b1bad43fdfd2b17be2096148e713192433c2dd915996ef63baeac8ef95901db6650d75e55f57aac196cff6b3dc3bd203f" },
                { "ta", "18875728e89fa2377a5770af7c32fa33059c1c843fad7aed9bf903a154c62a29b059166c90a9e5ab35a0d22ee2c3c61b2614c9f9a94d40b87693b54211c91149" },
                { "te", "cd8e219154e4f3c935eca6360023ab45828c43edc46011b13952aee11a3ffabe5de33a7501875135b5e7eeb0c20053cd6d20f6d35115daa217b7f5d7b2c15567" },
                { "tg", "e6a9ec0a34c390de6cb123c23c2cebc41292d312d24b045cd6cc4a2bfccefba17829a684473ffa7b9705b7c063f7c06b868e3f1a1ab51f6c3ca42ce478f9c27e" },
                { "th", "38ead3dada8f24e2262915ecd282639223cab48c97146ae975efe15c18837177cd544c95fa4c270670b31f01eaf6a336e10327e4906fba9708a1c0220507136b" },
                { "tl", "ff648ab3c71447d193f46f3f15cff24077c1a85ac6bd2a8d9d076c0d5bb17b52a38c02138e65355556419813150a89f2466fcc9653a8900f9e8073b68a6e1583" },
                { "tr", "5f36badbd1cdb85c5087df5d83f70e5c0784aa99dbce13c45e59e6c68b5dc7410e9bd6cc7504ee1c69e0dfc4f6bea9c483709a432915b177f0a6da61bf5c05ec" },
                { "trs", "ed231413223805d57deb878c654aaf2b7d01467d166701211fc60d845886cfbe23c32434ad9456807464fec01905b4d0ad2596723acd784c13faca49fea6a113" },
                { "uk", "9479d59da2c6a1a55e654e789fbd8b6fc269f05854f72339e404b36e75d412dbd0438c07ab5284fb4c99945421523c08ea680973e47ae86f891dc044a6db09ad" },
                { "ur", "b1eb1437cbe04c79812bc5f6f4c3dc9cb490de78824bb8cb346234ddb1f7264bee81bcf26b9636b0df8b56a0d78c295a6cd8495e4bc1a0e76593e069b3766dea" },
                { "uz", "e0c9fcc269d39387e3350ce33ce9b8f6f1aa1f21dbb8537af6f637b38ceb9f176c2acab7acb5de1e47e696a8e19c5cd4572235f6e35d168357b7211882dee986" },
                { "vi", "64622a4cb931b9bddf5cdd9308a510d256b35b7913281dd943848945a5b4f93974913d7603e53ee3e4868db2361dc8034877a6c53802adb009f338224b480c12" },
                { "xh", "2ee519c1482746390979b89a03074e286e17a23232725aa871cb769da7854097354a6262ce5d073f4014721311b7eeb64e65abebedb6e2cd36c2974747a9f1fa" },
                { "zh-CN", "15eb0aed1a838a7b04dd63d9738a72c80e4fddd23e5bcec047259911b4477a1e01fc3ee84a561d8887d2a00cfae358f18f6f09765698fec3b63b229df690a469" },
                { "zh-TW", "6ff1ff90b0f4f43004466e6268659711574bf3623b2fee1e0c2c254f0b0bb4305e359ef4d5b822e0c9103d31da986eb0eb0bfba282862347d93f0187cd98e4f5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "48bb53529cdf613b92054a0d984c2fe07384b28a223548f3cbb5c3fd477919257b2b753526eb16aa37500e8a8cfa0b142e4788124d2b7b218530c047b66ba774" },
                { "af", "e0e923e7fccacae12c00c1de1009442df3e7f89cfc65ec629eb6fb14276f5641a8387f9ebf4b3b944448cfe3f56549bff37d4910810d835aa6d183cb36343904" },
                { "an", "8464bde17e2f0293abe7f1739ab1b31d2465abe7cb7a3e60f2600f79942a14d298dc8cef4c6fc1fced7c8d77b33a2acc33dcfc36fd2274fa911ce433a29e06cf" },
                { "ar", "f49cfe79a64cdeda4ef5a23d8944ad3e2d5d65893b836432e01be88414ab1e6ab6dc2c9984ca58423fdce807df2b88c38078150ae3820f202fe674a7617f4c27" },
                { "ast", "df3bc15e1fe7ae498fd133ccc3799949230ce0089493e7694cfed205ca97df886148b42e3915ed65132592b9e726f02dcc4edf6494976e860bbe94de0331581d" },
                { "az", "e381f4ab9774a260c7b612cf6f36b9885986539bd2785c29f60fdee9239967f2d00dca286bbeace13719be133e69de9d5391f6c1227981be4d78f70254b07e4d" },
                { "be", "8ff6f47e462557bc06ff7bf385d28bac8d70fee4efdad0e7591c595f98838c6001a7b2e2171575fa2b526a04cb2639737475948a7ab127603f969ed8498345cd" },
                { "bg", "5271f3b0c5f7e7568178bb9237e2fcf6b34c19d989bb9614ff9f84c3d31e67ffc7397e3de91f5148b2193ed4f7ac010d054220de472de8ba4dd8c519b927e79c" },
                { "bn", "50986003b94c1c802d67e238b550324419b6c654ac0abd4ccb74f720fd0c06f25f4835a7c8791c34221cc0ce7898e09b898a0d9dac12399e5bb520fe8caa6afd" },
                { "br", "d6945a76a96ca50e0bb896f82969203e9ad570040acb9918f00524e69107dcc886c7d50efd4fe7548226e009ac7e6465d119f79edeeedf8af5ccfa16504d9587" },
                { "bs", "2d9eebe6b8e11bf57df8d38c1ac5e79aceee22c34dd78f36fac42f3f0caeaed57cf8435add8bf67a252ba8e223af5babfc78ee5aad3da489a3d4822fa1b5e693" },
                { "ca", "3466cd33cab064d9ce68b654de63e4aa9f906cc1dd1e9a5aa9a8790e96ddd6a0c559f6d9a27af406ad144e760e8c271a047bbd8f766f454a10945bca2136497e" },
                { "cak", "18587cd6cc35a5283a8a45dcd490631269d526e9cac42118b5457d2a672cd46f86bd687f3d83d302a78e347d8c92392863e8d2ac726e1c75cf7e7e2624818b11" },
                { "cs", "bcf85fbcf42e0812c53a61f5e2d8ec2cae9c5eb827814b35618750ece5f1032f8b4e3c0acce091f09881fa754962151ed67015e5adf6dadedfd33075d3ca6299" },
                { "cy", "fa38b8b0826dba42bd8c39c4de08971ab3113edd014891ded62096d5eb2422e91544d87603252fc51626236512c0b0f277f50129882d760805e05663608abf3f" },
                { "da", "fb15e800b62a2487118556d01ca699fadacab1918c9f80303a5a6c728bddffd59415da38e6d69551d793812f9090899a463fb9ee7b46ad646ecc3a582656c050" },
                { "de", "9e4dcd964bad4f1af66ec99908fd5bb9b2b91b6c82fff24ddc06d2e16b30842e6f4df8d05989f8b2f158826fc0269f149be0ca552036f3c7190ebd8f0e60884a" },
                { "dsb", "be62f9f4dc8050c1b25e9cab0817aac4e7bb8cb7d59fd9024c90caa81b01221faca607fa093d10db9deb3532cf5722bcf3cb4cf21b95c182babe4e5612a9f260" },
                { "el", "6655893b982eea2788302cd8ac05189efe28fed60e7dc8a97860d69746dd44ea8ded23e81492bc1e1d0874c664c087234ce19beb7b21e3e40856aaf907a81e0a" },
                { "en-CA", "eab263434f00c7fd0a43e48d70acf318abdc3f3c9632bb7c840d0ac91f3c3fdf1c9791c852c964fd8d869a7f15a8a11544a42310c2a97ce5beca41cbe261a8ef" },
                { "en-GB", "0c07a9438e10324e111d1a204dcbd472a122f2db05b32cc9daf4d063365289ff46ff9e38c273dd4a0978d8f2d656db0b8ccdb7a8a7033bd003b8628462e8f7d3" },
                { "en-US", "a9e3a5c1522a9a9df30c8baff019f13f219c4dce867c2122fcd17d3dd5e8c7c46be116297968f6b419491d1f1b424e1e1c5f76970f9badf7db8d92b4a5719340" },
                { "eo", "8768bd9426e4c493185572b0a319576a1198392302a8328e84f13eff58dbda8f42efe56a19b2ea80c7323a0394e66961dd3a96b1f834dde70ec5cded59c65769" },
                { "es-AR", "399534b1e3e027b857464790243be5cf068f1f8bad70eae4806c1e8dfa96c556e8492838270c268357640206f9654e05f8525cb4419e8d7c31d1ba5ab2d6a397" },
                { "es-CL", "c90acb7fef9e9b4b8c01f4c82551ba734a981f84815481c3c46d4e9b5a982f53a66712a4f2db885aba2ed1ffc3199f42ecdcf7a008b286b7255dd825f83135d1" },
                { "es-ES", "90f722f5804b29aec2033cd6333a2a7a7a121a8a8d090fc3800a67c1bbde674757245ac46eccb7fcf0f540748ed82687e015b1fb1f4643395402a27b2b349056" },
                { "es-MX", "28a8637ad551ea189600cd55b1ad193751501afed980f3d126da5ea9317e9ea9f44033e621c87c5a2b233f9a86a6fa287d4c8ea3fbaf693353cdb5237d78ac42" },
                { "et", "16b3ce01ca77e29f7ca1fcda97ea39b09d29c4cfdb87d78c41d3f29dcc9d3d55ba5c0dfd269bfd3879f60827430509ffc4726860899f225598a92dc8a736ce14" },
                { "eu", "d9840ea02d211d8649ce5331e8a22ae7f5e3fbfc8dc4b40cc4bafc240e4a9e0a99b0a4c470aafc847d42d1af14c940924c230e6f3661dfaaea1619ebbcbbb4f2" },
                { "fa", "6e967ac076ddf04e1497512f50f948631ab56937a48928b339127e157f299da4b4d7317b2f66077e72768cccb58e2f863a2a495aadbd8324acb6fc31e1e0da18" },
                { "ff", "9977412daa7e3ee6a7cf6ff33c7489364dae51549436ad3dc44192dfddf4744191987acdd5ffba5bcdcfba664c8246ea1f55e9bf0bc625d52e0988535af45e07" },
                { "fi", "91410bddc02b247b11f3797e6deaa4e6af256e822d4c67aa41af982761597b1b04e7d1a7efed9fa0526d2ad1d115734ffa3e47036c541ba103f859281de27b92" },
                { "fr", "a4e636efe3516f99f868a951e0f446a00b7a84025ca9fe0ba2f66302eea1254fc9aade74aa945c4128e01573687ca8a4c5dc6d041f3dc5bea93a0f024bd578e0" },
                { "fur", "3c59f1bebbca8099ed86143215cee2b0c73df82687fedb93194296a9b442f76a4111a287b6e5736cc6677da76bc90f6f9997be16b622e014f24b6aad05b33e0e" },
                { "fy-NL", "6fe5886344f3b23cb439855be9d45808ca13a6ebd4dbe7a52643d2e89173aaa29f6f080b2b8f1e2d141e48c0531a132a17463d957e4a8a48f3e98ed1cb26560e" },
                { "ga-IE", "e8b55fb4cc442f638304b09caeba68c94fe04005842ff42ceb2a4b1de8ff1a10a8c7a25da259637c566a2bd4b701822d337eb764ab80aff3efe7cd6044471101" },
                { "gd", "7e93aec75858b93622d76c6d926d810e5b720c6ee31e9fd300fc5cdd72332f5b5630d1d5706c0d268c70679da3de90b7e63f8e42b3b584a5dc3eba5155c2827e" },
                { "gl", "4c76f0def7ee02cb96e556b09f0364382786843627ffd4c1f0dbffc8b8149e683f6410b9b73ce12e0a5ec5106f2f11c9c364d110a6ec8a4b71166430d592a684" },
                { "gn", "5408bf6db252ef9d6088cfdafbf144dc85ac9e9ee8e33a772922955a5bf89004dafacdb91da110a9e958e0a1c18a74db7b28dcea35a9d4960785e243f6a6f89a" },
                { "gu-IN", "f7c89fc350fed2d5e66507f8d201af2ca83c184df6c05e26d4e514265864a126967dbf5c46061a72cded727b3ebeb230abf77d2a01b8bb4753c8da389e350103" },
                { "he", "c7cd291bdcf8d0eb590546b1adafaa26c794d6b843f4a261cd223aaf18fa4e5fd181b68c792fbdfec81cc9182acb7dcede7b5235efa0a01aa78dcff6f323bb10" },
                { "hi-IN", "2843a9a46eac4c209363b03af8349e270a387976c317286ba60db9cc4b4c8810b37cc4cb14db5893263aa68b30cdb106ffcb554171932d219ff1e09beb58a57d" },
                { "hr", "bbca89655a8646f073993c1dcb89d7c2ced5526c042c0c741e88f5fa305db0ee598f6559c50a333d6452334fc98e68396cd0e44901d042a0e1764ab656f69e01" },
                { "hsb", "c31a13e56d9e862ab909669475b0eb8b07fb31c9dec1a46d25a98c2627bc248d1b0626a1fe4e795b6c2483bb3702344dae364df12e483992c115312b0012053b" },
                { "hu", "bd7584a4bb858a713f273f86208efcfd3d2af1d877c7f08264d5076ac280f2e7316dc4b66f49af43321493574a279f6168e0cb99d875ec1da2ae818f226b0519" },
                { "hy-AM", "86a697a9371fce0b87ee783167d5259bc958223d7c3893c7318a18444ce6b220bddc8433f6c2fceaf0e2360bed00069e23adb7155bb9c585c81298a8d0e13f39" },
                { "ia", "f7846de6289e1eff9c82891e35c13a67db3e2a459fb34a54088746da503f330df5f46bee0772ee612a7444117d9514fda80ad56163b3dacde82e0182bb45e3fd" },
                { "id", "121b0554cb35d535b8607338da6af83c7220a3607b8b37759562eafc95afb46c6fb251c097dec9bfee64a23596894194101509dc3988fae9aae223fd73fbfeee" },
                { "is", "8b8219bb032e7e320cdea792da7e52cb81286c44d28679832ea3b92bca824ffe040841916d2c15cc68140abd4b650c758b533bcd0c9a8559f37c36802cd854c3" },
                { "it", "eb929533b8683132f33c3595f8b1ced75893b6f811c1e99014c4ddcb106c73c38a7b807296fde56a1576161edfe42e64a7b431831de8d7342d5703f882beb2b9" },
                { "ja", "3d74f2464dac289e108f8eaab3ba9806a03a235c34c047ddbdaeeb73c7eff2c4aa28141faa5f67cff447d48be5fc057f006134a6b561fb85be72603b978011e1" },
                { "ka", "3da0fb7be704bd9a3e8d770532fd692365645ba18c6f6351794bca90fa42b9f4269ad723e31ebbc98497f0294884b582824a7e14cccf0c4f8d3359309d9783e1" },
                { "kab", "4243ed15287bf551f4b9055b6e095f6c6618ca0ea93227e5f0d3854fa5555f0dfe0c24a057c830299874465e3bee5ec63810089508c695e1c1de5d1e3d2ca8f2" },
                { "kk", "7550955d73c30d77c97a253ef9238dfb8ae21c21aa840a10664c0c01e81027a9c73304d234b340a660a5580f0f2aaeabe72e737365c1fa8ff4be976f0f7de7b4" },
                { "km", "8aab2f2b2c0f85c79fb178dc5334656c667dd408e13c46703c4dbb06fa1be0a9f9695f8d2f17dec3517214a9bff1c35602ea0c7244177282ca958c7beff02d75" },
                { "kn", "9ac221d8e825f269ee77e80e4852b033e3baaeb399757b3a2747cd4f197221c6b218353767fe2dea0dd87d20ebe1a354e7bb2c2003737f9d01f7839f8bb0dbac" },
                { "ko", "5d467c8b7c83fa4efe7fcd30b7009f7271ba89e60b45437b20fde8a5fc4b8b2c0c3180c043d3bf13410a3e906276ea899c087f2b414d3ec31cbe3f35653f8686" },
                { "lij", "5992037585e75e0645e7c039a9027252cd014dc7aa187a9126211a97a2940958a4ed04414f76fab805c8bc727c3c2b56a00f465dc85320eec68d1ffbad690ab4" },
                { "lt", "70957eda9f3eea5f5754c4ac0d3c20ed747149f7bb3b87e73fcff5bd81dcab8601606177f6d61eb33942f3ba726b064165a1efa1a8b8a6be884a93673c602285" },
                { "lv", "fc9ae979e48d1340120d9cb31c8e9e7057dfc8c05d4b1d22281b5f04641c55a80094deb25195547a415f733e8c76024bd7ff6e0068d3c101c77a313756a1946a" },
                { "mk", "57f43df2e07027b9c5f7c4eba3d650c4399b94b822ad14c3821d1ae80743f50eccddd1d4cf0af9acf274c514c3c559aa8da89326e31eb671c544be56443bdf05" },
                { "mr", "1f25e55bd40369b68ea4710ee3454b591a8a4eec89f3c2ed3d6a4ba79c6be3a42ce1ea9334de0e71d80d3f0fca96e0a6181097736b0d49cdc67e2fcf22ba483e" },
                { "ms", "51b137b0775c6fc9821947abc1456ab974f99aa8d491fc135918ae48768a9adf2621d209b45a4d58e261ff4fe208fd7874551cde7140998a8302d64ad3558a22" },
                { "my", "ac74c881aaa5c970d020da6306f439937b066180733ec9ccd2b12065adf215687514e7a0c82861f61ec7da6111443e3ac932bc2a4f5f34d51f2093ef24fabb25" },
                { "nb-NO", "59c4c1bff8ce2eebf129e275fa4ad11e4ba06c0ecd0f25023dcf5977b3af88a74ed11a607137eb2ff2f2ea801b295644fc7a87cd87a51ef971e187fc475092f1" },
                { "ne-NP", "84eb40c43ac55f734a5b8a67226992a75de05c2ea758f5a8892d1d8322e9d8760e768e09f51265ca13fe96e069dd9c473c23b7f1af4ccb009c4b4324fa8fdbde" },
                { "nl", "b06d8f87f7210add613e2ae3dfe84c06feeb17fb49e0c8c0444dc5f69e4ff213e083b720ccc786c1da439ac75036f07e610f94a6d53d80c3c7a2c3d26fafd418" },
                { "nn-NO", "8e40f029da4702687c239d53e6ec93478f0b3b50ccc7541c15cdde83d78921c968e420f004e87689544a62da6fd77f3bc6adb11257ed8e41bb98b2f755977693" },
                { "oc", "0805af6b0c214496ceaef1cb2a7474e50bbd5b3ca7ff394f4ba084dd5e1b1846bd3196987b68acf816378e95349575a32a517ecf0a6ef6f5a91080b0ec6822fd" },
                { "pa-IN", "f19be201ed0c2f37d0f6d8a7f5b81d988dd3674313d136f29cdbcf5a991cb585017da9a513a3eef0cb021f9be23bb09ad8878de91936a0ab5ee9a1df24c9c2b4" },
                { "pl", "ec30b00bd0ab7543638f7cad49565ba3e417b3fa2583d9a870e590278ce897054afaf88612d46811d04f66dd19cd99f8e70120f2ae2a85c3ccd2d03b4bb33a3a" },
                { "pt-BR", "a81ffe6213f3748cf2b263986cbaf5dd8e5770887e8bffa27a6b46ad2f03e89afc38e5fa627f934d630c49d79d38f60a4304591916620e57221b5b4c487b9340" },
                { "pt-PT", "9d732ec33bd6f49b24d60d2af5e2f2dc8a13b95a4ca1ae2cbc78a4a172d0263a11acf84544fc188b92ea77ad958fa69cc723d198e8b3e58e1de24befa6da5f45" },
                { "rm", "bb327513d464def1c6775d7fd13680e990496e5165288b0e1d42d305beb54b63d10f4f28b18f38b070ad7058e7e7c58a582ee76903356cc04d6795bd7aea19da" },
                { "ro", "4b69976d694d63696effa68cd918e548d861d7d3f0cc87c8e2705fa3369dcba40539b4dd5da7ad65b2cee65a323ae9031f34144510ab078a18499d83ed999d69" },
                { "ru", "7b56bb576d107baf87be310583d3bbc4dcf173245d2658ae1b64676ccb9b840ffd7a0a3323f37f657152c856b600f188ec7951453b5b9e3bb3e22d85de0ed208" },
                { "sat", "d2f051ffce96141435aa2a3e96d97f56a5ee6950baf53f29b1a7574ff19522f52159f743623bb4119dde9c6cf9f3fad2089cfaebdd9e08b7f6e600548ac16f78" },
                { "sc", "25ca34f4ad469d63acbe0703efd86b1723ef0a67e4ac1b879ab168b8489695af18dcc8c051f611bef13cc8e4f4a87114fa3f1b0df896d2d42587afb8daeea1e0" },
                { "sco", "2abe183e609dbf2ecaa90113c824dedcc1bd1f05f192e47d9ebe682a1fc48c3474d96a424b8ce376ff685e97475cff4845f93ae2e5c480e66f1ea7dcb26c1d32" },
                { "si", "5b482e745b2daa29a804bc6e6ff48ff739abe94303c9a4fc2e52f3ec23d863b81084375e791266545e50eb9b6679211c75d197b0936569874685dcbbcfe8733e" },
                { "sk", "c2ca569afb2852125d42169444641373e02f6bc11f18b012f1222480ca5c3754593de4599655e686b9065d56925a9e1e66d51e7208ec1538d33bd1b1ab6e865a" },
                { "skr", "a8ba5e36431087dba57da3337a06684611f1cbe516705477f02ae8553e84dc9288c0403cdf0911e4e79eb0d02b2315e467d45ca2e202585ce9223f2d1d4ab43e" },
                { "sl", "5b838196cac095db1b3b91c86b384572a6fa5ed354043990f7f5809bf794ec2757299a0e8cdab086a18a2e120b2fbf474d05286c042223a636c0af953351ccc6" },
                { "son", "7149af67e2574af7ddcace44f628836e9ab1c61e1b4e258f912b67e8b66960c2fa19c0fae2698e3ec4d9cff9ea7f263bcd4b624de98a24e5c52379a6a881c7fb" },
                { "sq", "47dd87a002c6417a827172e0ffdf5e07e3754dc1d70fa2f5a2acd041e56316225fad68e255d78da42710171db093c17a43bacfc75df64d8ebd78a3611dfd1e8b" },
                { "sr", "212469c2e864101b79bda0f637ad9d7a0d37ef00de0333e21a734621e977952ae96e822468c676786e2bfef45ae949c082882ef9791551d4143e1b4038d3586d" },
                { "sv-SE", "40b1feba7af5963aba0be82cb5752d35c651d9d3c9edda934ba6ecde9a9c7561fa2a1af4de940f51f6df68ba70c5c683ae800627bff86e046027fc0cc17d815b" },
                { "szl", "94bf44c8646b2d4872f6c277bd70ffc52b11bb2d2054a28d23a5f0888c31619677d1ecad656340be381ba18d20173226dbf0dbf6689a1ceff37c347c121300b1" },
                { "ta", "22b90fee09265bce84d404425fc0fa47779e5ca7702e1efb44b8001d454f87035e37d7d1f719252e5e3e041ca14910423628b27219758e82ec9cbe7735a3a88b" },
                { "te", "ebe114800b241b1849e33732c214aac0c781c2f6fa78ec212ad8941d674a5b9d6d46986e97cf773eecb6983504fb534625c4b211659e692fb50594bdf1cef6f4" },
                { "tg", "e1d895f45493b13d1b15c9692bc184da7926de4e8827c61ae6091c52484c80ad695f3c2ab40312ac8a826e7d39d15b81bc0115fe83fd8bd0bca526905859f394" },
                { "th", "b4601b2855f9cfdb9894272461e3fc0ddc1b6c7e30426d109828d3a0f4d7818f88affd3db6e6e5c4f7c26fb888daa1b72a9c1273f4350b839bc19b041668946f" },
                { "tl", "73e2b5d4e4b8b7855f56c35d37241f5163411bc6bed6bcffe63f75efa9640cad72788c1374ea6fc41a4d86f34c5be95dce4a16ab57db970eb823db5cbc96496b" },
                { "tr", "baad9c44c3ca73277622e737b15de308572d0517f74c86f1236e3845ec925c1b18255d34355bab79272cde46751d39083f027ac216e990787a578b5f1b806491" },
                { "trs", "ff4644ae51bae9b28cfcbb3f6e7c219486b4a8497fbb30da524760f77d74d596f1e634cab4634c3dca8ae3242884ac50ce801369399f609fba16f63d11f32f84" },
                { "uk", "ff43bd66ae93e02ff1efe3f028be713a5bf91812a65dec0fde31d24c0b6cc8629e1c8333c68f93eba1d2227993dc2523e103ade8d1055e2516ad9fa39f9e3722" },
                { "ur", "fb419e10322a505da822009c998de5b4d22843f76eb9fbaffbff4315c90d0c6a95e80263717b6447f0cefc13d0549e4186c6bfd82f253ad4d98bd8b92bfc28ab" },
                { "uz", "3481422a73067d6a18d0c883df2daba0a9133fd8d1b442dc720fa2b569eb7e99df04709c52d17cb54301c0c9d0146b3d1843ae9df657c34ec4b2929d81c5bf7a" },
                { "vi", "e2332b7a3374c6510089e7a9c96a7bc3a8d83f999458d7976953b5dfedf087f3e1943a75049385cc61c920564723383a4f5ce7f4d2ce73460ef34f0e6931352d" },
                { "xh", "8d90585ed43d2f9a06d62c89cdc4a95f4a55edab88564b14ef8e6b8a56a5b18aae718561b1b533674cb03de83fc19b6b1c709487a1b62848632c551a9487c742" },
                { "zh-CN", "0a43ddbb3fd23ffc1fef5efbb97b44d7fc4e3234f22bc6f51b415f2cde3bdace63961b7dbd640647c087d5dafd24168c91419d47af46ac41960ebe7a1863280d" },
                { "zh-TW", "4554393e26d72b223496cc411143c410023682a79fa81909515af0c267ec527a752503ce642415ecd5b4d01eb788a7a9182806219d9bbd8243c7db13e592bc5f" }
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

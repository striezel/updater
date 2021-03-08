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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 5, 12, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.8.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "89a6a5492eefc80c21d20e36cfe473b7544de93c416cfea63073c84e461a59a997e5b61607dd53b5dfaa16e2076d86f8364e9ccc8989c2c99ee13e5ce838fc49" },
                { "ar", "a36e1f94f784701ce30302808b666ff6f9e45f0a452ee84fdeffadd1d50a5cb0f8d23bb373794718fe9d4798cbd153c95b93495a836301ed4d3c57993e12b3e9" },
                { "ast", "813bb178bc3de67aa77efca89e05ad0bdd55103e4974ca89f5b7966a7e31be0d46f783825df36f855bce7370267254bc717a629e136cc4addc2d001aabf6bedb" },
                { "be", "0bf18e86dfb36acdccb739ac475b690d473eece7a511ed1853363458714d87e657732558704cdd02d2e4ad1e5a5262d2f2ff6bc48726f2e07e3c8956d8f77a67" },
                { "bg", "7ceea657a279a376759604da9668d151b57abcfc765e3d32a50075dd92916daa413c8fd1e14f8e1645d92b006d07f62b2bc6c612280db9fe3615f067449789e0" },
                { "br", "bc6d8404166de0ae77b603357a0463869f21a58a919e38c74aaa1097516adc7a72ba86e13d0c5fc43526152fce4c16dbec3bb0c3bcb8437ee032e70b51ffec38" },
                { "ca", "8655666f98e5b2b7af3635b8663b2ba75c69a63ba2b6bcaeaa143025ac2e07644f4d95b01de6264ea12b2cfae046ea40578a2ba44a1c67536ddd672de57a0418" },
                { "cak", "e45ac138eb5cf2c827a703ee20e0c96c3f055adda57f1c00e4177bff9a1bea8c040a2704b45bf7a2fd7f294bbda29b8fc1c593af852a1ab07ee40d807c28750d" },
                { "cs", "cbcae75a363487795ee952de94aa823beb9939b0dc7b6b74b7f566b1af3c140f821f704d48065590731c5514fb59fed7164a4d7fdf2dece60bfd6953425fba02" },
                { "cy", "8d4f6ff8501178917e774b0ec66a726e5989185ce59dffe0c3706bed846364b60f94f3cf3e01d8421792e39c8829338aea34eaad40786fbae74a700191e4baa3" },
                { "da", "f335b6ca554d2568db1ffbed7c7e256455f1a1374bef569f47eafe3765c135140939248b2e5a1e352fe9127069f501164f9befb788fefc55a77a6a054cb49a32" },
                { "de", "5820735fd7b7f0abd4420f4fb43e1920c62a31ae9e18672902d5ead6aa9041f524334580043822c443ae7ffe5ed1ac7d295286f22d915b269d8adc37e581b70e" },
                { "dsb", "68bf7d7e82ad86aa76e6f49fb77959dd995a69fe819b7e70215dd40515d780f99cfece12bce66e851cd5301096ec37596179cf1fea24f914efb69d8ffd35c51f" },
                { "el", "7c730cabdb5ca958e8932fcc33c1abe39ddf1f683a1225856dbeaa7169e7637a24ddc1ea6501dbeb54e8f2778bf31ac6a875c44cd55b1ee5c1640dd5b7a78cca" },
                { "en-CA", "9993a1a7886c80e7e6bcaf89d3133477ecb4feed6c9b7439e02dff915b85168a18daaad0b55977d2f63c6b6d0e773045c641451fcd229bbb144913170215fb5d" },
                { "en-GB", "5444689b0d1be3543b8a7cf8b399dfbb74c80457b796a2c51c856da5ccb0f3abc97f7b88cc3e12e141e494334b211537016c5ef205f547a16645a6af34ecf22f" },
                { "en-US", "c3f16fa1023679419051f8d891b16fe96308aeec304e3b748433963bc28f79e22509479bfa1b35f14520ba003b1850310cb5eb740a0f86327fc6a27f312db574" },
                { "es-AR", "e3e791e18af5d9787a3ea1975f3fbda45c99827753c339bee74e2f9aa2d72d3120a73dc0efb14a31ca44810525c184133d04a744d812ca7559dc32abc756dff6" },
                { "es-ES", "1b03aa380a6f872013ef347fb79f7fae3b46b8db725090198bb2cde98540d4935ab4487c56bfb285b3679e937ecdd56735e419b756d3be575c9baf996856274e" },
                { "et", "9394156fb78dcd4092a01c800e94d1b615d2065018dba7005188856ceaf947ef35c0bfa18a9aca28f008ee891d9d2017b21d48600650c144d6b348307fadc136" },
                { "eu", "db59be674304ada524b3876ebff4c144ba4de18c029b691cab17771fd8373e228839c780112fc420c99cd7b61cfb59d582c072651de7ce78d3a7626b5d1b41dc" },
                { "fa", "8f44b45c65b22209522c921f0ae953920d8bcb0cd74747adb44510175c963f12cd3e87a3326ee48142e2f33848ddb7ccc7be8327f1d3fe587c0abea3de4a6302" },
                { "fi", "2272979087a4a183691d7f44bfcf3b9d2a7022ba75d62b0aedf4ac7ded5b6d322e29e69de1e967b00f9b557507b2c6e2516d488d321e79603e9b5fb2614fd225" },
                { "fr", "3e1acc406fa23a372317f8d3d9ce222b4a1211d481edf5f8577dd344b29592e5d05d1d51f5ca35b420b46c69c837bec08b350c8c0a521b810f355a1d9f5dc3a7" },
                { "fy-NL", "4688dda77c2459c67e66b394d2977d456e24f9affa3d45915e2e8f31ba16ee30882ae9f0a48c3778949b78918884337fd2331d9b083eb7cda0de30867769e255" },
                { "ga-IE", "56cf64baf732f8d796e3ee894f68e0767145a1eece128fb627e6c2bea133a681ce0fc5cad952d0d66f553d49153ba515126dd6c45f97a7dddf9864ee44a62a2b" },
                { "gd", "8a278f9310b12f3e9cf504235ec3085c8fd511040b4760408419731dc14bc43bfbe562e4b587af1cd78bdbc49e8438d17db5a28970cc9105282e370ba1909165" },
                { "gl", "72c00a93466ab87d0c052822d3330187dd722bbef3bc01a73b9a2673ce6b013c27a35833e571a9a7e55dba039a6466c4322a9821dd9e4a0ba2997ffae940a1c6" },
                { "he", "410a1b2c5cb2c6482a1b49c659d466d7353a55246c8883e30dbd34bb287342cf2222a672ce4b43ffb9d1e5983531c1f74ecf93911fee58f3630a31aeb8f07389" },
                { "hr", "f50ace617af314f0874644b8b20fdf8c8a18566c83b7484ce486c0757af1e1df79b3c9a4348c9b1af4d947e1271ef700f76ac75dda68018b56046635fa4851f4" },
                { "hsb", "2647019a4a91b52f50bfd0bc3e64de5fc5d29f22bc90a70cb12e8bdae3aa90b3f3d898ed6d10229192efedf7baadbebedfbf88e59070d0475f27be46ca80c32a" },
                { "hu", "b9bc8cf634e377e6b16bd7e6cbd77d720072ccc4e1c032e941bb7a3923768a2bffe5e4df4b77088354039b51f1bb4dbbbc76b0588591b318590d4f2475e0725d" },
                { "hy-AM", "2ee4978616d34c91350673e6d5303f699a1737a2b1331e1b2f7295ed458f3a3ed25dccf6d5398bde8c352afc7d9aea54182e34393f35b928229a71e4d295df01" },
                { "id", "bbee4ae1bf896c4b7dc2b556be35ac3ee3c0e5571ccd88475df6aca7cd8d693d9bf000645715283ec4dad003fc612ba7137a5df987726305c0cdbdc172156967" },
                { "is", "1c4da790871fea81688200818fb44c08d5c45578170c1ee140edc021a37cf02613800f6834915481bf914f53bb5900fa7b8964976aa6eda4b305aacc16af6384" },
                { "it", "96f08f0763910e40d1fac9e133afa26164ec4d5c9bae49eb2b88e1e5513f3d23450f65513deb3081c2aaeb84b080652afb344ef3fa080ccfb85ddf6f4a602f0f" },
                { "ja", "1b4473f322ed607a3f4bd8066c0146d894517a298be510c0741752ef66d187f027a1b91aa0849bb1da53c89ffe9cf3c5fc9b3ec668b2ac02259d81baf992fc3f" },
                { "ka", "22e20851fbfc9dda7a39eb0f6c62330cc8cb3a173894c18644db4dde6dcfcf1a72354ca5a28b2dde65ed31869250089e09a67e8428e95a34dd8e414c0ada38cb" },
                { "kab", "4bc8435a2f8f3a8792d448bae9031cba4b292d75000656b2bed2021ff4f0b90c062f80f20c9c5db4299896e13d8b23750a03d9432e181ca3ae8d74bb321af5ef" },
                { "kk", "43af79e09bf543c35f31d3361324348c0c7824aac5196e788fc0618d2508c988d5afdc7a67214df4936cd7a356f6dca0b51696f045dfdb58bd393c17338803c9" },
                { "ko", "cb1ac40a37ae9f6877674e3abd38a602161b94606850e4e9fa42b828f3f79dbd7d855153069ea2267d14521c8ede4184b65d3a2113bdd0cae09b33c668625451" },
                { "lt", "8bc043fa4ae3d7f4a7447ffd5ad2979e5f4e42c97bfcac4bcab35ae888a6d1d6c9cb4dfe9f1a8e3936ea339965126928d7a03bf026a9d52ed1e6778a23ec2108" },
                { "ms", "ac8fd873b49ee83fe923e622861ad79e63a24ae82a308581e2819a5aaf9693bec310cdcd483c75f33a6bf89ec9f7f736477dfb314c641a4021fbdf44b383f5e1" },
                { "nb-NO", "6fbb05deadf62f520547d9d4881dcf823747b60b48abbcde0f51cd48cafe7ab6de6815925bb05241e6d427d4f3dc22c69f40720215a99292edec43a45ae8c373" },
                { "nl", "881c638173a290bd23044bc41bcae6e8c2c104aa287611b6eedda5aaf20d567535560418169b20c43efaddb21f585b37d673e5ad645ff486ff444a2730040269" },
                { "nn-NO", "ea346507a0f172976fd8e14b72da122bf6add705acc87a181ce852734d62eda67474d9b6c75f889961142b5a9b242718317f28997d5cc3d6274ab7be7fef11ae" },
                { "pa-IN", "c5dc804b12375202e1bb80690038d6f2432456aed34d9882d4db50d8b501bb3b04f6e36c905791cb165e29bff08fa4210e422e93f73d196e384d80be5118afcc" },
                { "pl", "7c5779224d49515a1477fa9251f53f35eb24993411548c7388f1de47caa3e4ee6e210cb59cc9e18cbcaed58aceb18bb319480385d7780c8847f4548e8ce9ef52" },
                { "pt-BR", "4d8997afc22d7751321aaa3c10c10b7eb2b814d4891fc105ab89df1959f46a43fb85e5ec6845fdfc5ebbe55592d31a7b531d6a7e4f02b273ecbe379b20d739a7" },
                { "pt-PT", "98651f2efad17d8f69709b22ff937fe7781a5933bca887a2576c47e70adc8bf286d5f6c12deef7af8a746d67a9195f03055cc0e2fb923536d737cfa87c4a6e7b" },
                { "rm", "db281c0689c5a961dbd8e7a78a341b3f88e3215024f43d42b26596eb24e541fe1de12825ba17c2f1d391f4ca412c43905c78ed1d0315c2103148e41776ea1b9b" },
                { "ro", "1297df46a0a8c703dd0801119b1a0c2416312709457d75cd32c3e9c02ea8d16d75b7564c4539d88199924b5245a4f00584c0614c4ac231c476a1b0d590303a08" },
                { "ru", "9976348c92bce9eec5cbec0f81a8b6724015b4daea82c3bee03307f9c43adc3205b419c87fee128ff8e6614dbe6f1824463f55d85f6dfb9f1e40a3b0eca59378" },
                { "si", "b66a586ec99583d22020c300f425a000bfc41a85289f29e7f3b74b757199460f8c2aca92e79ee31514be94f6ba1d6cef25a87c3928bd11fc66357ff422bc74d4" },
                { "sk", "4cfb121f913924077e473f012c8b4a490777764567b5d0a7afa64f5488029d43cb2f12794673a49ef9213a1caacaaeb61f7ef5499c3c2ada859ae1ed5781c581" },
                { "sl", "7642373a560b4ebb393567808647befcec85a476c13871681db61a6430e884b3e03cdf11dc340076740b770e7a3ee3ce88f25e36b4848cc734d7e2ee1254f000" },
                { "sq", "098648a6817eefa9280a92cfd0a945883ed28b351390ffb3c5fe087da38b9359a71521e459ec0fbffa9311664e4db8d189b71ddc17b3dc7826d136100db1b686" },
                { "sr", "5235b479217ed126853d82b51a122395b43eeb6d04705056bc988c227a9c24846d08602c26fc92c5f918960cd99cbbfa31beedb7a1d9a9e3aa58f8cc21775055" },
                { "sv-SE", "050f08e33c725365dbc2546b010f68589f81d9ce30904a1e99bf4b96361607919601a7ce4ef3de2f937257e55dd39770ff7aaf5fad74d731bf72a53730a40605" },
                { "th", "64106c5b6519a85483c1e7116c32c93f01bab1356e65e7789aac283af41ef239b6da1b2b80660380982a6825c869aba176cc754cd7cf53e062e6c6300162d51d" },
                { "tr", "1da0f2c64eb79e6967fa2c11b5f3a2cd1c023ae32b8db4d451b847b4d07d1302d9d8e991079037a4d0703406ea7235162e4f18ed4f57299622bc58f2b1270418" },
                { "uk", "4f29ff9d6c0ab00b21841a5c9196c9736b1a2e7e122511a45b61f34b4ce4499b0c4a6c04e4bd5aa3efc20bc8404d5da88fae916e828d7643ef0c8e193a8b14f5" },
                { "uz", "f42e28243218d205794c43eae634bbbc7ed4bc36c8af8646a1bdda1dfc370e179b7d48bea8a8adc37e29db5d3f80e435eee98058dc156e7c2633eccd490143c6" },
                { "vi", "3c01ceb3b294857b7506edc84e673fb112ec3131d6604920b44d151fb521da4941bbb0ef5a07eb2069c121e887c75e4b173145ac67ff1a6ebf24ae5b07105a58" },
                { "zh-CN", "d238a1c846bf2f1baeb244edc5ed1308257ab93e5d6814e88406c08c886e0dfc2818edcbf0f11f49925b0b0b12dccd8d3412dba31bc359aecb3b1f821b7eaed6" },
                { "zh-TW", "c8b0ff0b38743ac126728db336290be187e42cc1f39f039f146ecc6a1dcb8e637e301cc7b8630d4ced9bb97f44be807c446e591aa1127d79a6002dbce3984ab5" }
            };            
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.8.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ae2c59d57ad922c46bfd7045fac8fbd12a4dad771f6f742b03d8f29a8cbe235a329841173bd2a2258cbeb9d1822be77875c0ad09b4a40c5cc842c8a664fe8234" },
                { "ar", "ba9bb62f0b4b45d5b55bb1e28f6320f73186ab2c2040a1474097a259a48ed476fccc966d5703407957675661a0834e94f23285caf536173eb419e6c55bd14bb5" },
                { "ast", "297197b4a50781004c665939d6228136e5c5c2b7dce083e30315ffd0037cafda75d516f5126299c9bc5622b5aea84ff8880bbd19a15768a692bcb3483e6528e8" },
                { "be", "a6a0b6d6b6f4a4fec525cee15564524630595978755a45f7183fe01f3d6c45b37e155d86ae98b05debe58d22f3f90751d17de9b57d59a1cec3f56cd5ee07beed" },
                { "bg", "05dcda4867d3b51aaaa7da24717ac0fa962ba9faac563242ad0d253d7e6c47287ecebcd197ffc9ba329a60f4a952cc87721ace0f4543327535906b6cd7aa6d59" },
                { "br", "d0a730a1a4b04c5d02d9a2c18ba83e63cde13c2adf2571c268aea4c967c249737f59412338007882deb5839896c1ff0ef18a1f3a30ed60e96265735eb5e8de19" },
                { "ca", "0435427d173e08c3a92b7583e33900279705a070f5f3f13f67365ccbbd10d3de26dd067cb9c1c91c2c571c46f572d95d45fa35822ed983714c613ac5860b2146" },
                { "cak", "acf0856d075e952747d7857a2d1cc94d4a772ce260c1916f597e94b5d4c608738ae2a5736fa9486a944ae27eb0e38b34fefe902f8f2cfc8aa7b03af299f45d99" },
                { "cs", "1e66958392adac340ddd043fcd68941f7b0a63b72966551a831814e99927dbaf776fda50c993c81bbc8478f8e8a461348160745bd5051854f04f30b927ed222c" },
                { "cy", "de057fb88b72ef13bebe83a2b36581ab7abe599ae85a28191554b2a6c449500f1e69bb4f0f289d5d32d3b06260024308e3c0ce3ec0c3c41e53489e613e0e0c51" },
                { "da", "e7a1e92e22f6f7cfac61311ec40cfe4aa2518997d479c61a4ae79904e5d6a1d6a69c96fe4ae86ed95d62364d75a0bcb2084d47b25bfb890be7deb959676c0660" },
                { "de", "a16757848f3217dfa131d2b5f31500b4dce82e210b4527a93327d475feca0d2689d3a3c702d97d8ce287f8f6255db35f807e9692520a43c5edd85650b93a3199" },
                { "dsb", "ef469a4d2683bcaee438cb265ac2c80886f2e28d59cb4c1df26369cdc084acfe81b34a79749b5bb5a702501c8e65c87fac45ffd8d82544e76edf8464dea737b7" },
                { "el", "c3315de72368199730e73899b5e7d71fd1537e1b902860003d7060688dbf36b5d64ac37a3a2e2851832421669ed2c0cfd734d7aa7eed85810e0f99c8db12b97d" },
                { "en-CA", "50a3d2d12d1eacd4940a3ec53a8bed9246d415839ec44db6dadebab78dc2051ee9eee183b0a4d0038b465b8236590da503d1c8a6d59e2bbb66d3536f8a4db654" },
                { "en-GB", "62a18753821c6afeb00eddd7fa76a3e357bb6edecdce46be33a1ecf01a9fd7047651fc359352dab5fe44c0002cbc35df11243430ed1a2cf9f1271596642ef79c" },
                { "en-US", "fb1820219987e12250f4d08f39ce83123b1859575a859fb1a33894641ed7ed121ece00bb245b76951c2bb85349ae9382761d67815bd2f0dea49ca197f70a4e35" },
                { "es-AR", "7e20d631eb3bdad68d20f7f73477e16754e483d328b96fc5c12905644f0706c61f2869985e332fbbed480c7b298dfd9234c91dcf88b133d5dce37984a38a87be" },
                { "es-ES", "077374713a0a5e664de602520a5c2d856db3bdd8f61043ef2d74aa286cab4553eac5de5d4763a6b3c0078e8a9684317deacda266a2f57adefb98019858ce1f02" },
                { "et", "5f15308c0478909ec9861e81ccc66d46663fd6de4f46c0026176679fd1786a5c6258dfefcad95746064a2cf19b9d11c9fab77a448aac65930fee32ee609c9b94" },
                { "eu", "1669156365639d44c89d8ee5819a050d6a7cbba7a2350186f13645b11be3e51158a4270f0aad2cba002f6f9b7de17632a57cd00626801e9a2eb90c823025b491" },
                { "fa", "295075d3c08edf5e71cdeed22123413999daf37be67be4a8b16de61bf3bbb32bd93ac8183991d119b626354627f858fe381039ff5292dd9a2bb46ad4fa288cdc" },
                { "fi", "c496e030e199e6eab60fceeff565ad703aaafbb2a1db3c1dd7ec66076ad198683f50fb5b3cd086427601a0bc3de9edba64b09de24759f65614ef0e1df1ea49d0" },
                { "fr", "8054965d5d77351d63243542c5108a5524bd6aa63bab72dcfccba3f1038e93d571441652a2ff0a8ad887b13ed7e565f3bc0ebf7d6c5b1719b4c08132d7b44724" },
                { "fy-NL", "97ffadf63e5cf22a23270cb82019fa25e948daec902866053c2bc54b445e1194a9fa98d17a194eaa3121da9f10eef624fcc43a59b89074b2f4106bc2147efaa6" },
                { "ga-IE", "498aaadf593d38b1b62ff90f7f88ad0cf5b90c50a12f98608891960ceb70cd0001919ddaec134689ee937f1bf3d3ec5dc836703d9eb158a5e8158caef6851588" },
                { "gd", "5c8e87a8776011d8ea8a41b3184405ba82a70a64233f44ff883492e66b006807963386205eff6c40c1f01354c9be6b93cb23ded47e17d183554057900523763c" },
                { "gl", "94649e17cd9a862eb6857d0f2d534a10a31b113d964bff8970fc8b81618f9a6e2135d1a06c6bbce4449a1130ce803aae312eafbf0e95f1e0152ce2fda085b023" },
                { "he", "00cc5761121f72e142f6851d75fbd8077acd89ddba69b51a2cb190d091088710a8297dc43a5269f8992554cd6b8766252686fb98b0b0d6f482aea3d18191110e" },
                { "hr", "5dac70b4e75f1793bf40280e384c6234f4d05d0fe555fd791c3303543ed665576fb7a57b2fd6120c063ed6531ba0df80580a2b4afde79f9a61102ae01557f84e" },
                { "hsb", "b21b5d9e43f000bc7226aa006ca3fe2eda4940356ff4999f73b5981aa379e98c74a0966463118c199c1758c5c4d07d97d15ff775c302b5740e7aa8e05bf67d54" },
                { "hu", "6273d6d9535b54db9c4343656bdb985752fc7fc17b5840c0afccdfd78ef51b060a018a66210c135cc36d1e39e22112f2e63a13f9ab3aeaf8d9109acfbf3b5a97" },
                { "hy-AM", "0c807074fd2023d4d9027f6d27c8e7f312b2caaed9dbfe32d6f8920088a7ea965b704c16aac308129ba1e6ababdf698e5b0e9bdb5d115806309112b94f4cd26b" },
                { "id", "88669f5829fe23d85cd12292f47350782e1eb814893c9ada275e71d1ad20b6f39a8846f519b601eb2919a19f195c04b2bafa16b65339dde8b667d5e8f1bd3ed5" },
                { "is", "1f303de81f3b2781b0fb9df7d62ba1508b46cac1a629652335d4c74d12ea3a976ad1e972bd55ce60545a07ce65426779abbe0c2b404d98c438bede5021e08850" },
                { "it", "b37de103bd8c29ccb6e66cf2cd7aae13f6c16e6a03b9168f5d275b681d7d0f62d6907fd57d2a50622439e8b7030cc5af1b34cffea622afb5c8e26f7d8d284159" },
                { "ja", "4f344e4b9b46014cfd8b0a8974c3e28b30b40f8fa8dc007e5c88dd0c32a71bcd5857742ddacd36b55eb732f461cb3d29548804f3b247fc6d3b4447ecbb6f1fb6" },
                { "ka", "e1f8f3daf895330385cce6039398cea3c5acce6d2e6e91f584a1556bb926806f60a592a34b10331ad41a9207d7f9e95540dbead8c321d8645a91d752ee38df3e" },
                { "kab", "cfd102559e3e2a5b63445fc33f4bf9a9d2caa2b3d5db488427b40bb42317418127fe6566d5ad2260fece20d6526d0883b05550c9efe058177779f634e47fcdd1" },
                { "kk", "e3517feb158aff3e7426630dff8401c9dab48e491bbfe8e75f94e59fa7b0c8d0a3d837c34bf05f940c4c2181bd7626c1e7c5d1ee198449fecfd6d3f6dd0d4ad0" },
                { "ko", "e883451fced1b193154432daed6d94503cb76773056b443c1ad856363abaadaff5e6ab2cb667af2f408bbd7a9b23c827bbe198e0e785b63824f266799929b1f2" },
                { "lt", "bde4f9a182c798a3233facee2a1476952fc4ad497f609b3d09b679ffde8970294246266bf3bb9a13b8ab262ffb66cafab5fe8e9d036781cac9bdd6a34c481956" },
                { "ms", "7ae5131a92558bedccc89e0832f804be88ca197fe77b68b71cb8d166d2ffcaefe7c38d92f73bf7168d0bf9bbba6d900c4fcba51dd9d9a6005a3b0f0eec34ba16" },
                { "nb-NO", "379f8d6579b2b7f891cb4cf51c59c26a06d136968d180d76a0c29d7927f1d27f69e2d88b26b7ca89c0e186cfd523081f68204b763d3f70a6e0c7dc76d14a480e" },
                { "nl", "725f3f8b4e5aba9a2cb18928d2527036441b5cf32417fa91ee8d3a92fd3017a8532b242384736b561365fdd1a79181dbae657d781c31620238236f776aa285d7" },
                { "nn-NO", "02b7ea910e23058a466477844d23787f99658bdb2ad44306b309897007bceca5180e386b17ed487e2f72202b9cb6ddec6332293f6c628b10a062bd873eee38c6" },
                { "pa-IN", "5645a3665da0108780aa8bfbbb1e855a1f647666f7530f4baa8efc1779e5aa2dc830b1259fa3a437cb194001793e61cfdadd838976de03d35d18e0a4483594bc" },
                { "pl", "11b1c5d74ac7a676c9747ffba0a6499f0109a30bb950acd86e32fe67d8910dbc991be79bcede8c289838eaf83d6453efea9ae284ca60ba3835bca0b5ca0717bb" },
                { "pt-BR", "d5c349c89bfbdfc8759ddafa4b1487d953bbf73b4db2e4674e999ed1198e6e38c546dfce74dc92e05d456e02e5e70d5e2d8bcef6d55bcf1cc3c33608a74040e6" },
                { "pt-PT", "660a7585bb6c9232571f7a32eda7e0feddc0a4983adb1302e9a47d8aeda93c248e1bd6dad22f80a63986b7e4ec0a9b98d8b6c5124783d240975d434bdd2913fb" },
                { "rm", "a5d1d52b317fb02cc0aa61bd59cd8c7c7b4c212e3d2e7fdf886825f90c3600cb3ff61de123b1968f0476dc47df3990b28f656fc786604f20b9e52ac8de5559e8" },
                { "ro", "c57f2dd4b347647052c3eb93f60610667e88883b40cc5b1d599f1ff07e45f7749c31e199ff23b2790ad57affe29c5b20d1a6d6c5cc89506fc8f0fcf44f34b152" },
                { "ru", "c604eea0c9f0e75bf3dfba982389df935ba04b108f139823e15c2725f840214a126beb1fcd8cd03efdb591314027d0ca1671ee2f6b49861a85462ba9237ffef9" },
                { "si", "4eb97e8ace24fb50d45a0a0c223ec73e38bdab82b09c2967850b08761ef4a960ba2d77922c39ff2bb5f286ac2cd978acf2809fd6853b1a3fdfa84397c73524b0" },
                { "sk", "99a1fdca35c891b6cde5d389b5eb7b24c0396bf03081db3b824c7443cb234015dd06db1af6132f4afd64739b3bdf5bac66d89f7e8139b5690a4f926d7aee9340" },
                { "sl", "03aee0da4fab476d9f720ad7dc4bb79cd8bc588b5f864fa652c324da7b5f28fa091e4b04f06c7749dd5c45ed3520e1adc9bd469e4e228053f691924b831c7401" },
                { "sq", "c982a9adfb38311b83eba63712fd854f471c67dfb39123782373efc072c6bcae44ca7dd34f5c494248a4e25d51be341359db2c52dd9f93a60eb8d07f1abb4604" },
                { "sr", "938a4539d73993028af51889c7fb7bd033e089d0940c022b8aadcef024572d123366dbaa9cacc4da08a759bd1d63eba74ef9ae430727cb7147fe56b28903521b" },
                { "sv-SE", "c01994f1686c4471f9c6d303a0f1d7ebb104431028ce8255c559c656eacff30f95930ada77bb216fa5eb3998cfbc7f19056b90dee52b758c99bef9c88abfd1f7" },
                { "th", "91c5e6e3dd9c1f6bfd49e14c8dee8ea70b76d4f1dcfcd1e984957d7e5ef03386a39633fb0aa10ac8e9a7b3fbfcdb9e05f32847e13e811fae14d90fda36ed0a75" },
                { "tr", "c3d9b2709ed35d799cf382e9764294fa8af4c8808cc289baf2de76a359b16c73d1749801a0f3d018631f5f9594c32c80ab31988357b6d018d604a2ede7126be1" },
                { "uk", "f374a13b26b637997293558ff204c2ae04258bb4724a79e364f25f4a7e05f172936eaa395c5db95b17c736f3384d87b6e0e252146daf128101db07a5048a60c7" },
                { "uz", "5806478f6ab1a6558347da884b556588fb1144e9a1aace345d3c2154ef09e0001a5a10c0f86aa047285d60a6f525a80d75c8f6a157148b5897405eaa27b28e9a" },
                { "vi", "c052a52f3e33e2968e3e5bc45e08d7d355cf4050fc097781f91c64c33bf393b1659931266ded0b81f70ea8917537e2b6a2a4bc95b818a238cde35c6c3965d96b" },
                { "zh-CN", "09474de19e7ea04ce4420b37c61f2f11e0825a3413915e1d4fad735b5adce23a7389b49c1d3cf89e039f09ddc6e2e363169f02c543c7dd68fc64d1f6e3c0110d" },
                { "zh-TW", "e1a521381c74eea40e55c1f1bf4e95f6bcd991847aa2de304bebae962cd1e26a91f46eee1696da20631ede93f7e6b7c016c0b2ff8678d8743c92de65ba6344de" }
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
            const string version = "78.8.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate proess returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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

    } // class
} // namespace

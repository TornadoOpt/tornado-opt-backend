// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            11705477509410479242182510843072266476033358736050337996184225833669105715382,
            9062827731153514437911190243323454241833331927659942139970241114603305316153
    ];
    uint256[2][2] G_2 = [
        [
            2607418484182204738758171587696264213393472142068281831577379813218799268223,
            3626324571993353471186314315018704530776496504442935363587255821981022730899
        ],
        [
            11805068613629534258288403502427857405653347810917872356243001158651385685674,
            7992555288270710459536526877184825929686980699970499338469683863685209919619
        ]
    ];
    uint256[2][2] VK = [
        [
            9681155670853189948589136988750173764262498032673337998598192470522131582817,
            16458760229501199899775592832368761527835530700862217075655543784835240602071
        ],
        [
            7361098345736027428888742753138192003920852813490333759580555706353812118559,
            18444545890885154984692004314447913562428108524925994458310392347195047598233
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 12309728050529616206531403792373159930604125642319918594010825422285257454836;
    uint256 constant alphay  = 1112740759080638811286411064835720919806528423217582199224757765133136951127;
    uint256 constant betax1  = 14426368935067719563953383349101032832068891153931297601482898896733523158054;
    uint256 constant betax2  = 142926828088233334551585599040735554707901322810690288777973081082715025467;
    uint256 constant betay1  = 4482987173129030661296454650855833017665062200665368469114050659311483049794;
    uint256 constant betay2  = 15578529404089678405182417736080619983643955304782631319127544061048267736917;
    uint256 constant gammax1 = 14507074556315927107781967461999072486719679909406141877939816099905401305237;
    uint256 constant gammax2 = 19827931212016229261878048040238926246102319447687126266875354929485736475871;
    uint256 constant gammay1 = 20169778653307107537740042298098573329325947551163861813901134717754927640394;
    uint256 constant gammay2 = 16243603985632620242257165525860323512918051456333190744268860785860829504884;
    uint256 constant deltax1 = 12049081617860074553014014651971670446636921681222073733885231183375077329759;
    uint256 constant deltax2 = 20775393299300499757642987775318158824122684264423060966458647314784442702987;
    uint256 constant deltay1 = 1232044844596450503725290430093517365283992085260857420002559560339300491364;
    uint256 constant deltay2 = 1653126385206444758899696969600984372029123716841699954343359423346677506970;

    
    uint256 constant IC0x = 15111689969929084195292244414678792067617304331524266467108973518595838460633;
    uint256 constant IC0y = 15675287847110565778174078551782611399013117834056659700540004916858872223588;
    
    uint256 constant IC1x = 4057505453569755025513319122093208510708383736801624973460413282947786685843;
    uint256 constant IC1y = 333963549823287348656584391027729806771783773727289083341046594516618165749;
    
    uint256 constant IC2x = 14992226433833953297961336150616805425886718495778825064294645940749476611214;
    uint256 constant IC2y = 16785998574017793013130262655093056567216171756907420779940632451967172308;
    
    uint256 constant IC3x = 12166682480593465257811132992347956619205985725369581213520887664476008223020;
    uint256 constant IC3y = 2363506311475041469843952132240765311903860602819591532178017990599660500127;
    
    uint256 constant IC4x = 18453301972678279471650634337964358811562597953811575944332056771543734773848;
    uint256 constant IC4y = 6144420856581179065652731529425429568458256943410085739986629610343816688281;
    
    uint256 constant IC5x = 8379110739466392987694813999235714409199732317617853480473414665190462180456;
    uint256 constant IC5y = 3829893522367850028810869939931904959272417418044058642041415473981924737420;
    
    uint256 constant IC6x = 230452318022296690808482914934279275578703568236574531727794789968597629848;
    uint256 constant IC6y = 15900509156881453225798107038806946623578183961871501817127997526784446816447;
    
    uint256 constant IC7x = 7374497381886085813957757560654310355230040726611380684274925805134166261406;
    uint256 constant IC7y = 20197025040655621939179710499845379357659258588248773737165804351057399382996;
    
    uint256 constant IC8x = 10560842843604412334694112528420209053347915319835690920770829773015867670368;
    uint256 constant IC8y = 12624320871582487964717904302736244221836264806003296582651640726119993860773;
    
    uint256 constant IC9x = 19350522677690792556193718064500635104382524881289374820918994817443605879565;
    uint256 constant IC9y = 6552850361005421758180965318764835300935168213556040117674991291166476823263;
    
    uint256 constant IC10x = 6144506561184145844148361254577774697976380864644624203791151998544046290266;
    uint256 constant IC10y = 21534677326719388214465753981006922892838778118140787446501634359957005940391;
    
    uint256 constant IC11x = 4776267184230370850393315528958102481824706298823979597668694324862839462527;
    uint256 constant IC11y = 12250990193856542698272712573167681689647474549075953555257980433263789857567;
    
    uint256 constant IC12x = 8647874196821324778282592942871016325374383787033458802175013406310626076151;
    uint256 constant IC12y = 13646171566041523388145048685018727457991219202236983219630666742569211158090;
    
    uint256 constant IC13x = 6265991535500558369959855421515319762696555935874112927927892401301921355887;
    uint256 constant IC13y = 21547811732903634386431001151209707798715606847007122184689823248682290238830;
    
    uint256 constant IC14x = 19488788927071602667075439378115295725181432214033834930937495061149572727323;
    uint256 constant IC14y = 16536344221855068024868985722118228204023275622002858744497441758232044511717;
    
    uint256 constant IC15x = 2031436176644406964011414279868144200148206984524284346659275972483576534328;
    uint256 constant IC15y = 11570829481281923540497060966431096863397134716489292426762747472287184897135;
    
    uint256 constant IC16x = 4373732861745293523627212505682911581151140764455329330172468167781975683801;
    uint256 constant IC16y = 7717062090018212747247762264965317023198860335234634651538775038484700679794;
    
    uint256 constant IC17x = 8303581925683829851766440477792317774130832340899302533402695789729161305921;
    uint256 constant IC17y = 21568999093594541264854781427197093225232873361118082325591603025073077069862;
    
    uint256 constant IC18x = 5593527110934632210013468403105863286152934796905383530264367786355499652216;
    uint256 constant IC18y = 3047030743907911476893211218835711588392781663738292384196600830305939170143;
    
    uint256 constant IC19x = 11942134572967555024616482725574671370887670099897682808825379598806675188724;
    uint256 constant IC19y = 17441335030958212919621329384307324933472435919696949917514117470129189652528;
    
    uint256 constant IC20x = 11132680598697793015453662089532577407661009272874939710781990949934625280919;
    uint256 constant IC20y = 11865370602768372716061772759068467495333079069832167327875001779567447998019;
    
    uint256 constant IC21x = 14842443969937125506010646487794948477323286164376642975886428565289613652554;
    uint256 constant IC21y = 14548401429923343102820069269037101986702870235699275966430609539407299870579;
    
    uint256 constant IC22x = 18315735003912753193210522882727322236204421660996999035661426593933325803171;
    uint256 constant IC22y = 10853621921047429027185831475308387356627320016192362712384289660517759726174;
    
    uint256 constant IC23x = 14526348773474243338406568127921759385702912566073390329661256468176078830082;
    uint256 constant IC23y = 7622239561932703727083317023946894314050454613810774984727892517516483747050;
    
    uint256 constant IC24x = 16790487111874959658276379529462192920891671046316508503732581223582025917854;
    uint256 constant IC24y = 349548232092056138405175578111061320819332687779729698006339818099778043168;
    
    uint256 constant IC25x = 14931620085836726747115355309052563050107376297719226278025585319888265063801;
    uint256 constant IC25y = 16241805136191103832430945798186392906989411762579818168575560318455108687359;
    
    uint256 constant IC26x = 3799877324883860723685202676083305469272165803699002369105984498499688897856;
    uint256 constant IC26y = 16043293781677055711605710001790795704990608992730081326170078796115633832394;
    
    uint256 constant IC27x = 5612096684706864262600987970005267837318628157706409541073607872441046104696;
    uint256 constant IC27y = 3416943511534904856111524096949109050403075796690625731427878348918078198331;
    
    uint256 constant IC28x = 455383774761600423447704476494286066649873527485198557016874274967341841151;
    uint256 constant IC28y = 9537250971923313886992909978898427289878818823483848905481225347194169408727;
    
    uint256 constant IC29x = 20754902743901903158933738897943257319405535377027682932943584042825701611065;
    uint256 constant IC29y = 4968733827633729897033003114590479050192744784761890333635336055873017757820;
    
    uint256 constant IC30x = 19243649557189411102960957452582133039557258885334408677071116543332996850743;
    uint256 constant IC30y = 3981152492717848255312164364569588760672799921737114618107172192237773464563;
    
    uint256 constant IC31x = 19703893939671004259741678725943595126039017658792178298341571253913934156841;
    uint256 constant IC31y = 10085958260405236840034633935461202415684781555275110284108259246348797366334;
    
    uint256 constant IC32x = 10311834591286046091982245919815204571171094611044518909605874727826307679272;
    uint256 constant IC32y = 1097185394271143913728703354093135979714171964930793629724571845895974787529;
    
    uint256 constant IC33x = 4124586590808464309260262923956716715503872713384578464968032782649804453853;
    uint256 constant IC33y = 204043029240150431635860662665998409543674354187052539813285020856962838574;
    
    uint256 constant IC34x = 7020195740980868641144376487964965226403766279980132944248789256405338530659;
    uint256 constant IC34y = 5829210795564952012932047278518902254540820623164556380140130547789473696182;
    
    uint256 constant IC35x = 7681168212815790083329834185527835301692331745057500108611296251330419639725;
    uint256 constant IC35y = 13766425792817648041361526254080621800356459284155901212481113056788298193455;
    
    uint256 constant IC36x = 11752316431589021858428363072759440356740628673304750559966814425532067400442;
    uint256 constant IC36y = 9367551949608298224010128606895220662920614010834846386008070477002191994341;
    
    uint256 constant IC37x = 9204656472954743812293264206607394937770155521334384836252455598849778224676;
    uint256 constant IC37y = 8190591054564993405960739229028497300916248581230753650867003595106335531318;
    
    uint256 constant IC38x = 20286605459141752222211847888603326919821807607980876643426804110255139854963;
    uint256 constant IC38y = 16388298580852636151721119286312780015922616690221856083733094902220083827035;
    
    uint256 constant IC39x = 19123108145672193855641344934857212441728991466006900665213030834521908489930;
    uint256 constant IC39y = 19461436221309653075348512216174599074934665419302051338545127477042643727945;
    
    uint256 constant IC40x = 10780253235932138525340318008831338946744747877022649551213650403726729701638;
    uint256 constant IC40y = 4292487016490355152533142804860331396654501902964824592975492219863530740359;
    
    uint256 constant IC41x = 2508500347598173898392760098179211549794726348268466774979663673525666903645;
    uint256 constant IC41y = 1859078176228830840940633941836699135197184957872674796559806958316097940160;
    
    uint256 constant IC42x = 6622319005820277714836136182353908386967376092927327426713096805274383274597;
    uint256 constant IC42y = 10646756159988144568351295384283948991388727613110779563926393124197633428853;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[42] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))
                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))
                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))
                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))
                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            
            checkField(calldataload(add(_pubSignals, 1152)))
            
            checkField(calldataload(add(_pubSignals, 1184)))
            
            checkField(calldataload(add(_pubSignals, 1216)))
            
            checkField(calldataload(add(_pubSignals, 1248)))
            
            checkField(calldataload(add(_pubSignals, 1280)))
            
            checkField(calldataload(add(_pubSignals, 1312)))
            
            checkField(calldataload(add(_pubSignals, 1344)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[5] memory) {
        uint256[5] memory limbs;
        for (uint8 i = 0; i < 5; i++) {
            limbs[i] = (x >> (55 * i)) & ((1 << 55) - 1);
        }
        return limbs;
    }
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[7] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[42] memory public_inputs; 

        public_inputs[0] = 4705804686246180394250562843768140093955153318599703466890114696907018894456;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 6; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[5] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[5] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[8 + k] = cmW_x_limbs[k];
                    public_inputs[13 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[5] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[5] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 5; k++) {
                    public_inputs[18 + k] = cmE_x_limbs[k];
                    public_inputs[23 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[28] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[29] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[30] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[31] = challenge_W_challenge_E_kzg_evals[3];

            uint256[5] memory cmT_x_limbs;
            uint256[5] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 5; k++) {
                public_inputs[28 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[33 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }
}
package vm

import (
	"fmt"
	"net"
	"time"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"

	. "bosh-softlayer-cpi/softlayer/common"
	slhelper "bosh-softlayer-cpi/softlayer/common/helper"
	bslcstem "bosh-softlayer-cpi/softlayer/stemcell"
	datatypes "github.com/maximilien/softlayer-go/data_types"
	sl "github.com/maximilien/softlayer-go/softlayer"

	"bosh-softlayer-cpi/util"
	"strings"
	"math"
	"strconv"
)

type softLayerVirtualGuestCreator struct {
	softLayerClient sl.Client
	vmFinder        VMFinder
	agentOptions    AgentOptions
	registryOptions RegistryOptions
	featureOptions  FeatureOptions
	logger          boshlog.Logger
}

func NewSoftLayerCreator(vmFinder VMFinder, softLayerClient sl.Client, agentOptions AgentOptions, featureOptions FeatureOptions, registryOptions RegistryOptions, logger boshlog.Logger) VMCreator {
	slhelper.TIMEOUT = 120 * time.Minute
	slhelper.POLLING_INTERVAL = 5 * time.Second

	return &softLayerVirtualGuestCreator{
		vmFinder:        vmFinder,
		softLayerClient: softLayerClient,
		agentOptions:    agentOptions,
		registryOptions: registryOptions,
		featureOptions:  featureOptions,
		logger:          logger,
	}
}

func (c *softLayerVirtualGuestCreator) Create(agentID string, stemcell bslcstem.Stemcell, cloudProps VMCloudProperties, networks Networks, env Environment) (VM, error) {
	for _, network := range networks {
		switch network.Type {
		case "dynamic":
			if cloudProps.DisableOsReload || c.featureOptions.DisableOsReload {
				return c.createBySoftlayer(agentID, stemcell, cloudProps, networks, env)
			} else {
				if len(network.IP) == 0 {
					return c.createBySoftlayer(agentID, stemcell, cloudProps, networks, env)
				} else {
					return c.createByOSReload(agentID, stemcell, cloudProps, networks, env)
				}

			}
		case "vip":
			return nil, bosherr.Error("SoftLayer Not Support VIP netowrk")
		default:
			continue
		}
	}

	return nil, bosherr.Error("virtual guests must have exactly one dynamic network")
}

func (c *softLayerVirtualGuestCreator) GetAgentOptions() AgentOptions { return c.agentOptions }

func (c *softLayerVirtualGuestCreator) UpgradeInstanceConfig(id int, cpu int, memory int, network int, privateCPU bool) error {
	var err error
	until := time.Now().Add(time.Duration(1) * time.Hour)
	if err = c.WaitInstanceHasNoneActiveTransaction(id, until); err != nil {
		return bosherr.WrapError(err, "Waiting until instance has none active transaction before os_reload")
	}

	_, err = c.UpgradeInstance(id, cpu, memory, network, privateCPU, 0)
	if err != nil {
		if strings.Contains(err.Error(), "A current price was provided for the upgrade order") {
			return nil
		}
		return bosherr.WrapErrorf(err, "Upgrading configuration to virutal guest of  id '%d'", id)
	}

	until = time.Now().Add(time.Duration(1) * time.Hour)
	if err = c.WaitInstanceHasActiveTransaction(id, until); err != nil {
		return bosherr.WrapError(err, "Waiting until instance has active transaction after upgrading instance")
	}

	until = time.Now().Add(time.Duration(1) * time.Hour)
	if err = c.WaitInstanceHasNoneActiveTransaction(id, until); err != nil {
		return bosherr.WrapError(err, "Waiting until instance has none active transaction after upgrading instance")
	}

	until = time.Now().Add(time.Duration(1) * time.Hour)
	if err = c.WaitInstanceUntilReady(id, until); err != nil {
		return bosherr.WrapError(err, "Waiting until instance is ready after os_reload")
	}

	return nil
}

func (c *softLayerVirtualGuestCreator) WaitInstanceUntilReady(id int, until time.Time) error {
	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}
	for {
		virtualGuest, err := virtualGuestService.GetObject(id)
		if err != nil {
			return err
		}
		if virtualGuest.AccountId == -1 {
			return bosherr.WrapErrorf(err, "SoftLayer virtual guest '%d' does not exists", id)
		}

		lastReload, err := virtualGuestService.GetLastTransaction(id)
		if err != nil {
			return bosherr.WrapErrorf(err, "Getting last transaction of '%d'", id)
		}
		activeTxn, err := virtualGuestService.GetActiveTransaction(id)
		if err != nil {
			return bosherr.WrapErrorf(err, "Getting active transaction of '%d'", id)
		}

		virtualGuestService.GetPowerState(id)

		reloading := activeTxn != datatypes.SoftLayer_Provisioning_Version1_Transaction{} &&
			lastReload != datatypes.SoftLayer_Provisioning_Version1_Transaction{} &&
			activeTxn.Id == lastReload.Id
		if !reloading {
			powerState, err := virtualGuestService.GetPowerState(id)
			if err != nil {
				return bosherr.WrapErrorf(err, "Getting power state of '%d'", id)
			}
			if powerState.KeyName == "RUNNING" {
				return nil
			}
		}

		now := time.Now()
		if now.After(until) {
			return bosherr.Errorf("Power on virtual guest with id %d Time Out!", virtualGuest.Id)
		}

		min := math.Min(float64(10.0), float64(until.Sub(now)))
		time.Sleep(time.Duration(min) * time.Second)
	}
}

func (c *softLayerVirtualGuestCreator) WaitInstanceHasActiveTransaction(id int, until time.Time) error {
	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}
	for {
		trans, err := virtualGuestService.GetActiveTransactions(id)
		if err != nil {
			return bosherr.WrapError(err, "Getting active transactions from SoftLayer client")
		}
		if len(trans) != 0 {
			return nil
		}

		now := time.Now()
		if now.After(until) {
			return bosherr.Errorf("Wait instance with id of '%d' has active transaction time out", id)
		}

		min := math.Min(float64(5.0), float64(until.Sub(now)))
		time.Sleep(time.Duration(min) * time.Second)
	}
}

func (c *softLayerVirtualGuestCreator) WaitInstanceHasNoneActiveTransaction(id int, until time.Time) error {
	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}

	for {
		trans, err := virtualGuestService.GetActiveTransactions(id)
		if err != nil {
			return bosherr.WrapError(err, "Getting active transactions from SoftLayer client")
		}

		if len(trans) == 0 {
			return nil
		}

		now := time.Now()
		if now.After(until) {
			return bosherr.Errorf("Waiting instance with id of '%d' has none active transaction time out", id)
		}

		min := math.Min(float64(5.0), float64(until.Sub(now)))
		time.Sleep(time.Duration(min) * time.Second)
	}
}

func (c *softLayerVirtualGuestCreator) UpgradeInstance(id int, cpu int, memory int, network int, privateCPU bool, additional_diskSize int) (*datatypes.SoftLayer_Container_Product_Order_Receipt, error) {
	upgradeOptions := make(map[string]int)
	public := true
	if cpu != 0 {
		upgradeOptions["guest_core"] = cpu
	}
	if memory != 0 {
		upgradeOptions["ram"] = memory / 1024
	}
	if network != 0 {
		upgradeOptions["port_speed"] = network
	}
	if privateCPU == true {
		public = false
	}

	productPackageService, err := c.softLayerClient.GetSoftLayer_Product_Package_Service()
	if err != nil {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}

	packageType := "VIRTUAL_SERVER_INSTANCE"
	productPackages, err := productPackageService.GetPackagesByType(packageType)

	if err != nil {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapErrorf(err, "Getting package info by type: '%s'", packageType)
	}
	if len(productPackages) == 0 {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapErrorf(err, "No package found for type: '%s'", packageType)
	}
	packageID := productPackages[0].Id
	packageItems, err := productPackageService.GetItems(packageID, "")
	if err != nil {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapErrorf(err, "Getting package items of '%d'", packageID)
	}
	var prices = make([]datatypes.SoftLayer_Product_Item_Price, 0)
	for option, value := range upgradeOptions {
		priceID := getPriceIdForUpgrade(packageItems, option, value, public)
		if priceID == -1 {
			return &datatypes.SoftLayer_Container_Product_Order_Receipt{},
				bosherr.Errorf("Unable to find %s option with %d", option, value)
		}
		prices = append(prices, datatypes.SoftLayer_Product_Item_Price{Id: priceID})
	}

	if additional_diskSize != 0 {
		diskItemPrice, err := c.getUpgradeItemPriceForSecondDisk(id, additional_diskSize)
		if err != nil {
			return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapErrorf(err, "Getting upgrade item price for second disk of '%d'", id)
		}
		prices = append(prices, *diskItemPrice)
	}

	if len(prices) == 0 {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.Error("Unable to find price for upgrade")
	}
	order := datatypes.SoftLayer_Container_Product_Order{
		ComplexType: "SoftLayer_Container_Product_Order_Virtual_Guest_Upgrade",
		Prices:      prices,
		Properties: []datatypes.Property{
			{
				Name:  "MAINTENANCE_WINDOW",
				Value: time.Now().UTC().Format(time.RFC3339),
			},
			{
				Name:  "NOTE_GENERAL",
				Value: "Upgrade instance configuration.",
			},
		},
		VirtualGuests: []datatypes.VirtualGuest{
			{
				Id: id,
			},
		},
		PackageId: packageID,
	}

	upgradeOrder := datatypes.SoftLayer_Container_Product_Order_Virtual_Guest_Upgrade(order)

	productOrderService, err := c.softLayerClient.GetSoftLayer_Product_Order_Service()
	if err != nil {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapError(err, "Creating ProductOrderService from SoftLayer client")
	}
	orderReceipt, err := productOrderService.PlaceContainerOrderVirtualGuestUpgrade(upgradeOrder)
	if err != nil {
		return &datatypes.SoftLayer_Container_Product_Order_Receipt{}, bosherr.WrapErrorf(err, "Placing Container order to virtualGuest '%d'", upgradeOrder.PackageId)
	}

	return &orderReceipt, nil
}

// Private methods
func (c *softLayerVirtualGuestCreator) createBySoftlayer(agentID string, stemcell bslcstem.Stemcell, cloudProps VMCloudProperties, networks Networks, env Environment) (VM, error) {
	virtualGuestTemplate, err := CreateVirtualGuestTemplate(stemcell, cloudProps, networks, CreateUserDataForInstance(agentID, networks, c.registryOptions))
	if err != nil {
		return nil, bosherr.WrapError(err, "Creating VirtualGuest template")
	}

	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return nil, bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}

	virtualGuest, err := virtualGuestService.CreateObject(virtualGuestTemplate)
	if err != nil {
		return nil, bosherr.WrapError(err, "Creating VirtualGuest from SoftLayer client")
	}

	if cloudProps.EphemeralDiskSize == 0 {
		err = slhelper.WaitForVirtualGuestLastCompleteTransaction(c.softLayerClient, virtualGuest.Id, "Service Setup")
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Waiting for VirtualGuest `%d` has Service Setup transaction complete", virtualGuest.Id)
		}
	} else {
		err = slhelper.AttachEphemeralDiskToVirtualGuest(c.softLayerClient, virtualGuest.Id, cloudProps.EphemeralDiskSize, c.logger)
		if err != nil {
			return nil, bosherr.WrapError(err, fmt.Sprintf("Attaching ephemeral disk to VirtualGuest `%d`", virtualGuest.Id))
		}
	}

	vm, found, err := c.vmFinder.Find(virtualGuest.Id)
	if err != nil || !found {
		return nil, bosherr.WrapErrorf(err, "Cannot find VirtualGuest with id: %d.", virtualGuest.Id)
	}

	if cloudProps.DeployedByBoshCLI {
		err := UpdateEtcHostsOfBoshInit(slhelper.LocalDNSConfigurationFile, fmt.Sprintf("%s  %s", vm.GetPrimaryBackendIP(), vm.GetFullyQualifiedDomainName()))
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Updating BOSH director hostname/IP mapping entry in /etc/hosts")
		}
	} else {
		var boshIP string
		if cloudProps.BoshIp != "" {
			boshIP = cloudProps.BoshIp
		} else {
			boshIP, err = GetLocalIPAddressOfGivenInterface(slhelper.NetworkInterface)
			if err != nil {
				return nil, bosherr.WrapErrorf(err, fmt.Sprintf("Failed to get IP address of %s in local", slhelper.NetworkInterface))
			}
		}

		mbus, err := ParseMbusURL(c.agentOptions.Mbus, boshIP)
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Cannot construct mbus url.")
		}
		c.agentOptions.Mbus = mbus

		switch c.agentOptions.Blobstore.Provider {
		case BlobstoreTypeDav:
			davConf := DavConfig(c.agentOptions.Blobstore.Options)
			UpdateDavConfig(&davConf, boshIP)
		}
	}

	vm.ConfigureNetworks2(networks)

	agentEnv := CreateAgentUserData(agentID, cloudProps, networks, env, c.agentOptions)

	err = vm.UpdateAgentEnv(agentEnv)
	if err != nil {
		return nil, bosherr.WrapError(err, "Updating VM's agent env")
	}

	if len(c.agentOptions.VcapPassword) > 0 {
		err = vm.SetVcapPassword(c.agentOptions.VcapPassword)
		if err != nil {
			return nil, bosherr.WrapError(err, "Updating VM's vcap password")
		}
	}

	return vm, nil
}

func (c *softLayerVirtualGuestCreator) createByOSReload(agentID string, stemcell bslcstem.Stemcell, cloudProps VMCloudProperties, networks Networks, env Environment) (VM, error) {
	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return nil, bosherr.WrapError(err, "Creating VirtualGuestService from SoftLayer client")
	}

	var virtualGuest datatypes.SoftLayer_Virtual_Guest

	for _, network := range networks {
		switch network.Type {
		case "dynamic":
			if util.IsPrivateSubnet(net.ParseIP(network.IP)) {
				virtualGuest, err = virtualGuestService.GetObjectByPrimaryBackendIpAddress(network.IP)
			} else {
				virtualGuest, err = virtualGuestService.GetObjectByPrimaryIpAddress(network.IP)
			}
			if err != nil || virtualGuest.Id == 0 {
				return nil, bosherr.WrapErrorf(err, "Could not find VirtualGuest by ip address: %s", network.IP)
			}
		case "manual", "":
			continue
		default:
			return nil, bosherr.Errorf("unexpected network type: %s", network.Type)
		}
	}

	c.logger.Info(SOFTLAYER_VM_CREATOR_LOG_TAG, fmt.Sprintf("OS reload on VirtualGuest %d using stemcell %d", virtualGuest.Id, stemcell.ID()))

	vm, found, err := c.vmFinder.Find(virtualGuest.Id)
	if err != nil || !found {
		return nil, bosherr.WrapErrorf(err, "Cannot find virtualGuest with id: %d", virtualGuest.Id)
	}

	slhelper.TIMEOUT = 4 * time.Hour
	err = vm.ReloadOS(stemcell)
	if err != nil {
		return nil, bosherr.WrapError(err, "Failed to reload OS")
	}

	err = c.resizeByOrder(virtualGuest, vm.ID(), cloudProps)
	if err != nil {
		return nil, bosherr.WrapErrorf(err, "Resizing vm of `%d`", vm.ID())
	}

	err = UpdateDeviceName(virtualGuest.Id, virtualGuestService, cloudProps)
	if err != nil {
		return nil, err
	}

	if cloudProps.EphemeralDiskSize == 0 {
		err = slhelper.WaitForVirtualGuestLastCompleteTransaction(c.softLayerClient, vm.ID(), "Service Setup")
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Waiting for VirtualGuest `%d` has Service Setup transaction complete", vm.ID())
		}
	} else {
		err = slhelper.AttachEphemeralDiskToVirtualGuest(c.softLayerClient, vm.ID(), cloudProps.EphemeralDiskSize, c.logger)
		if err != nil {
			return nil, bosherr.WrapError(err, fmt.Sprintf("Attaching ephemeral disk to VirtualGuest `%d`", vm.ID()))
		}
	}

	if cloudProps.DeployedByBoshCLI {
		err := UpdateEtcHostsOfBoshInit(slhelper.LocalDNSConfigurationFile, fmt.Sprintf("%s  %s", vm.GetPrimaryBackendIP(), vm.GetFullyQualifiedDomainName()))
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Updating BOSH director hostname/IP mapping entry in /etc/hosts")
		}
	} else {
		var boshIP string
		if cloudProps.BoshIp != "" {
			boshIP = cloudProps.BoshIp
		} else {
			boshIP, err = GetLocalIPAddressOfGivenInterface(slhelper.NetworkInterface)
			if err != nil {
				return nil, bosherr.WrapErrorf(err, fmt.Sprintf("Failed to get IP address of %s in local", slhelper.NetworkInterface))
			}
		}

		mbus, err := ParseMbusURL(c.agentOptions.Mbus, boshIP)
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Cannot construct mbus url.")
		}
		c.agentOptions.Mbus = mbus

		switch c.agentOptions.Blobstore.Provider {
		case BlobstoreTypeDav:
			davConf := DavConfig(c.agentOptions.Blobstore.Options)
			UpdateDavConfig(&davConf, boshIP)
		}
	}

	vm, found, err = c.vmFinder.Find(virtualGuest.Id)
	if err != nil || !found {
		return nil, bosherr.WrapErrorf(err, "refresh VM with id: %d after os_reload", virtualGuest.Id)
	}

	vm.ConfigureNetworks2(networks)

	agentEnv := CreateAgentUserData(agentID, cloudProps, networks, env, c.agentOptions)
	if err != nil {
		return nil, bosherr.WrapErrorf(err, "Cannot create agent env for virtual guest with id: %d", vm.ID())
	}

	err = vm.UpdateAgentEnv(agentEnv)
	if err != nil {
		return nil, bosherr.WrapError(err, "Updating VM's agent env")
	}

	if len(c.agentOptions.VcapPassword) > 0 {
		err = vm.SetVcapPassword(c.agentOptions.VcapPassword)
		if err != nil {
			return nil, bosherr.WrapError(err, "Updating VM's vcap password")
		}
	}
	return vm, nil
}

func (c *softLayerVirtualGuestCreator) resizeByOrder(vm datatypes.SoftLayer_Virtual_Guest, cid int, cloudProps VMCloudProperties) error {

	if vm.StartCpus != cloudProps.StartCpus || vm.MaxMemory != cloudProps.MaxMemory ||
		vm.DedicatedAccountHostOnlyFlag != cloudProps.DedicatedAccountHostOnlyFlag {
		err := c.UpgradeInstanceConfig(cid, cloudProps.StartCpus, cloudProps.MaxMemory, 0, cloudProps.DedicatedAccountHostOnlyFlag)
		if err != nil {
			return bosherr.WrapErrorf(err, "Upgrading instance config of '%d' VM", cid)
		}
	}
	return nil
}

func (c *softLayerVirtualGuestCreator) getUpgradeItemPriceForSecondDisk(id int, diskSize int) (*datatypes.SoftLayer_Product_Item_Price, error) {
	virtualGuestService, err := c.softLayerClient.GetSoftLayer_Virtual_Guest_Service()
	if err != nil {
		return &datatypes.SoftLayer_Product_Item_Price{}, bosherr.WrapError(err, "Creating SoftLayer VirtualGuestService from client")
	}

	itemPrices, err := virtualGuestService.GetUpgradeItemPrices(id)
	if err != nil {
		return &datatypes.SoftLayer_Product_Item_Price{}, bosherr.WrapErrorf(err, "Getting upgrade item prices of '%d'", id)
	}

	var currentDiskCapacity int
	var diskType string
	var currentItemPrice datatypes.SoftLayer_Product_Item_Price

	diskTypeBool, err := virtualGuestService.GetLocalDiskFlag(id)
	if err != nil {
		return &datatypes.SoftLayer_Product_Item_Price{}, bosherr.WrapErrorf(err, "Getting local disk flag of '%d'", id)
	}

	if diskTypeBool {
		diskType = "(LOCAL)"
	} else {
		diskType = "(SAN)"
	}

	for _, itemPrice := range itemPrices {
		flag := false
		for _, category := range itemPrice.Categories {
			if category.CategoryCode == "guest_disk1" {
				flag = true
				break
			}
		}

		if flag && strings.Contains(itemPrice.Item.Description, diskType) {
			capacity, err := strconv.ParseInt(itemPrice.Item.Capacity, 10, 0)
			if err != nil {
				return &datatypes.SoftLayer_Product_Item_Price{}, err
			}
			capToCompare := int(capacity)
			if capToCompare >= diskSize {
				if currentItemPrice.Id == -1 || currentDiskCapacity >= capToCompare {
					currentItemPrice = itemPrice
					currentDiskCapacity = capToCompare
				}
			}
		}
	}

	if currentItemPrice.Id == -1 {
		return &datatypes.SoftLayer_Product_Item_Price{}, bosherr.Errorf("No proper %s disk for size %d", diskType, diskSize)
	}

	return &currentItemPrice, nil
}

func getPriceIdForUpgrade(packageItems []datatypes.SoftLayer_Product_Item, option string, value int, public bool) int {
	//mistake
	for _, item := range packageItems {
		isPrivate := strings.HasPrefix(item.Description, "Private")
		for _, price := range item.Prices {
			if price.LocationGroupId != -1 {
				continue
			}
			if len(price.Categories) == 0 {
				continue
			}
			for _, category := range price.Categories {
				if item.Capacity != "" {
					capacity, err := strconv.ParseFloat(item.Capacity, 64)
					if err != nil {
						return -1
					}
					if !(category.CategoryCode == option && strconv.FormatFloat(capacity, 'f', 0, 64) == strconv.Itoa(value)) {
						continue
					}
					if option == "guest_core" {
						if public && !isPrivate {
							return price.Id
						} else if !public && isPrivate {
							return price.Id
						}
					} else if option == "port_speed" {
						if strings.Contains(item.Description, "Public") {
							return price.Id
						}
					} else {
						return price.Id
					}
				}
			}
		}
	}
	return -1
}
